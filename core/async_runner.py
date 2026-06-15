"""
Async Runner — concurrent probe execution using threading.
Drops-in over runner.py for significant speed improvement.
Uses ThreadPoolExecutor (not asyncio) for compatibility with
sync HTTP clients (urllib, transformers pipeline).
"""

from __future__ import annotations
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict
from attacks import ATTACK_REGISTRY
from core.judge import RuleBasedJudge, LLMJudge, score_unbounded, Result
from core.cache import ProbeCache

rule_judge = RuleBasedJudge()


class AsyncRunner:
    def __init__(
        self,
        target,
        attack_names: List[str],
        max_probes: Optional[int],
        reporters: List,
        live_reporters: Optional[List] = None,
        verbose: bool = False,
        llm_judge_model: Optional[str] = None,
        dynamic_modules: Optional[Dict] = None,
        concurrency: int = 1,  # default 1 for CPU Ollama; increase if GPU
        use_cache: bool = True,
    ):
        self.target = target
        self.attack_names = attack_names
        self.max_probes = max_probes
        self.reporters = reporters
        self.live_reporters = live_reporters or []
        self.verbose = verbose
        self.llm_judge = LLMJudge(model=llm_judge_model) if llm_judge_model else None
        self.dynamic_modules = dynamic_modules or {}
        self.concurrency = concurrency
        self.cache = ProbeCache() if use_cache else None
        self.all_results: List[Result] = []

    def _get_module(self, name: str):
        if name in self.dynamic_modules:
            return self.dynamic_modules[name]
        return ATTACK_REGISTRY[name]()

    def _run_probe(self, probe_obj: dict, name: str) -> Result:
        """Run a single probe — called concurrently."""
        probe_text = probe_obj["text"]
        system     = probe_obj.get("system")
        category   = probe_obj.get("category", name)

        # Cache check
        if self.cache:
            cached = self.cache.get(
                probe_text,
                str(self.target),
                attack_module=name,
                category=category,
            )
            if cached:
                cached.reason += " [cached]"
                return cached

        response = self.target.generate(probe_text, system=system)

        if name == "unbounded_consumption":
            result = score_unbounded(probe_text, response.text, attack_module=name)
        else:
            result = rule_judge.score(
                probe=probe_text,
                response=response.text,
                category=category,
                attack_module=name,
            )

        # LLM judge escalation
        if self.llm_judge and result.confidence != "HIGH":
            result = self.llm_judge.recheck(result)

        # Cache store
        if self.cache:
            self.cache.set(probe_text, str(self.target), result)

        return result

    def run(self):
        judge_label = f"rule-based + LLM ({self.llm_judge.model})" if self.llm_judge else "rule-based"
        cache_label = f"cache={'on' if self.cache else 'off'}"

        print(f"\n{'='*64}")
        print(f"  LLM Red Team  [{cache_label}  workers={self.concurrency}]")
        print(f"  Target  : {self.target}")
        print(f"  Modules : {', '.join(self.attack_names)}")
        if self.dynamic_modules:
            print(f"  External: {', '.join(self.dynamic_modules.keys())}")
        print(f"  Judge   : {judge_label}")
        print(f"{'='*64}\n")

        t_total = time.time()

        all_module_names = self.attack_names + list(self.dynamic_modules.keys())
        for name in all_module_names:
            self._run_module_concurrent(name, self._get_module(name))

        elapsed = time.time() - t_total
        self._finalize(elapsed)

    def _run_module_concurrent(self, name: str, module):
        probes = module.probes()
        if self.max_probes:
            probes = probes[: self.max_probes]

        label = "[external]" if name in self.dynamic_modules else "[builtin] "
        print(f"{label} {name} — {len(probes)} probes  (concurrency={self.concurrency})")

        module_results = []
        t0 = time.time()

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {
                pool.submit(self._run_probe, probe_obj, name): probe_obj
                for probe_obj in probes
            }
            done = 0
            for future in as_completed(futures):
                done += 1
                try:
                    result = future.result()
                    module_results.append(result)
                    self.all_results.append(result)
                    status = "VULN" if not result.passed else "safe"
                    cached = " [cache]" if "[cached]" in result.reason else ""
                    if self.verbose:
                        print(f"  [{done:02d}/{len(probes)}] {status} score={result.score:.2f} conf={result.confidence}{cached}")
                    else:
                        # Always show basic progress so user knows it's not frozen
                        print(f"  [{done:02d}/{len(probes)}] {status}{cached}", end="\r", flush=True)
                except Exception as e:
                    print(f"  [error] {e}")

        elapsed = time.time() - t0
        vulns  = [r for r in module_results if not r.passed]
        pct    = len(vulns) / max(len(module_results), 1) * 100
        high   = sum(1 for r in module_results if r.confidence == "HIGH")
        medium = sum(1 for r in module_results if r.confidence == "MEDIUM")
        low    = sum(1 for r in module_results if r.confidence == "LOW")
        print(f"           → {len(vulns)}/{len(module_results)} vulnerable ({pct:.0f}%) | H:{high} M:{medium} L:{low} | {elapsed:.1f}s\n")
        self._emit_live_reports()

    def _finalize(self, total_elapsed: float):
        total  = len(self.all_results)
        vulns  = [r for r in self.all_results if not r.passed]
        medium = [r for r in self.all_results if r.confidence == "MEDIUM"]
        low    = [r for r in self.all_results if r.confidence == "LOW"]

        print(f"{'='*64}")
        print(f"  SUMMARY  (total time: {total_elapsed:.1f}s)")
        print(f"  Total probes : {total}")
        print(f"  Vulnerable   : {len(vulns)} ({len(vulns)/max(total,1)*100:.0f}%)")
        print(f"  Safe         : {total - len(vulns)}")
        print(f"  Speed        : {total/max(total_elapsed,0.1):.1f} probes/sec")

        if self.cache:
            hits = sum(1 for r in self.all_results if "[cached]" in r.reason)
            if hits:
                print(f"  Cache hits   : {hits}")

        if not self.llm_judge and (medium or low):
            print(f"\n  ⚠  {len(medium)} MEDIUM + {len(low)} LOW confidence results.")
            print(f"     Re-run with --llm-judge llama3 for better accuracy.")

        # Cross-verification
        builtin_r  = [r for r in self.all_results if r.attack_module in ATTACK_REGISTRY]
        external_r = [r for r in self.all_results if r.attack_module not in ATTACK_REGISTRY]
        if builtin_r and external_r:
            bv = sum(1 for r in builtin_r  if not r.passed) / len(builtin_r)  * 100
            ev = sum(1 for r in external_r if not r.passed) / len(external_r) * 100
            diff = abs(bv - ev)
            agree = "✓ consistent" if diff < 10 else f"⚠ divergence ({diff:.0f}%)"
            print(f"\n  Cross-verification: built-in {bv:.0f}% vs external {ev:.0f}% — {agree}")

        print(f"\n  By module:")
        by_module = {}
        for r in self.all_results:
            by_module.setdefault(r.attack_module, []).append(r)
        for mod, results in by_module.items():
            v   = sum(1 for r in results if not r.passed)
            tag = " [ext]" if mod not in ATTACK_REGISTRY else ""
            print(f"    {mod:<26} {v}/{len(results)} vulnerable{tag}")
        print(f"{'='*64}\n")

        for reporter in self.reporters:
            reporter.report(self.all_results)

    def _emit_live_reports(self):
        if not self.live_reporters:
            return
        for reporter in self.live_reporters:
            try:
                reporter.report(self.all_results)
            except Exception as e:
                print(f"[report] live update failed for {reporter.__class__.__name__}: {e}")
