"""
Runner — drives the red team session.
Handles both built-in attack modules and dynamically loaded external datasets.
"""

from __future__ import annotations
import time
from typing import List, Optional, Dict
from attacks import ATTACK_REGISTRY
from core.judge import RuleBasedJudge, LLMJudge, Result

rule_judge = RuleBasedJudge()


class Runner:
    def __init__(
        self,
        target,
        attack_names: List[str],
        max_probes: Optional[int],
        reporters: List,
        verbose: bool = False,
        llm_judge_model: Optional[str] = None,
        dynamic_modules: Optional[Dict] = None,  # external dataset objects
    ):
        self.target = target
        self.attack_names = attack_names
        self.max_probes = max_probes
        self.reporters = reporters
        self.verbose = verbose
        self.llm_judge = LLMJudge(model=llm_judge_model) if llm_judge_model else None
        self.dynamic_modules = dynamic_modules or {}
        self.all_results: List[Result] = []

    def _get_module(self, name: str):
        """Return an attack module instance by name."""
        if name in self.dynamic_modules:
            return self.dynamic_modules[name]   # already loaded
        return ATTACK_REGISTRY[name]()           # load a built-in module

    def run(self):
        judge_label = f"rule-based + LLM ({self.llm_judge.model})" if self.llm_judge else "rule-based"
        all_names = self.attack_names + list(self.dynamic_modules.keys())

        print(f"\n{'='*64}")
        print(f"  LLM Red Team")
        print(f"  Target  : {self.target}")
        print(f"  Modules : {', '.join(self.attack_names)}")
        if self.dynamic_modules:
            print(f"  External: {', '.join(self.dynamic_modules.keys())}")
        print(f"  Judge   : {judge_label}")
        print(f"{'='*64}\n")

        # Run built-in modules first, then external datasets.
        for name in self.attack_names:
            self._run_module(name, self._get_module(name))

        for name, module in self.dynamic_modules.items():
            self._run_module(name, module)

        self._finalize()

    def _run_module(self, name: str, module):
        probes = module.probes()
        if self.max_probes:
            probes = probes[: self.max_probes]

        label = "[external]" if name in self.dynamic_modules else "[builtin] "
        print(f"{label} {name} — {len(probes)} probes")

        module_results = []

        for i, probe_obj in enumerate(probes, 1):
            probe_text = probe_obj["text"]
            system     = probe_obj.get("system")
            category   = probe_obj.get("category", name)

            try:
                t0 = time.time()
                response = self.target.generate(probe_text, system=system)
                elapsed  = time.time() - t0

                if name == "unbounded_consumption":
                    from core.judge import score_unbounded
                    result = score_unbounded(
                        probe=probe_text,
                        response=response.text,
                        attack_module=name,
                    )
                else:
                    result = rule_judge.score(
                        probe=probe_text,
                        response=response.text,
                        category=category,
                        attack_module=name,
                    )

                escalated = False
                if self.llm_judge and result.confidence != "HIGH":
                    result = self.llm_judge.recheck(result)
                    escalated = True

                if self.verbose:
                    status = "VULN" if not result.passed else "safe"
                    esc    = " [escalated]" if escalated else ""
                    print(f"  [{i:02d}] {status} | score={result.score:.2f} | conf={result.confidence}{esc} | {elapsed:.1f}s")
                    print(f"       {result.reason}")

                module_results.append(result)
                self.all_results.append(result)

            except Exception as e:
                print(f"  [error] probe {i}: {e}")

        vulns  = [r for r in module_results if not r.passed]
        pct    = len(vulns) / max(len(module_results), 1) * 100
        high   = sum(1 for r in module_results if r.confidence == "HIGH")
        medium = sum(1 for r in module_results if r.confidence == "MEDIUM")
        low    = sum(1 for r in module_results if r.confidence == "LOW")
        print(f"           → {len(vulns)}/{len(module_results)} vulnerable ({pct:.0f}%) | H:{high} M:{medium} L:{low}\n")

    def _finalize(self):
        total  = len(self.all_results)
        vulns  = [r for r in self.all_results if not r.passed]
        safe   = total - len(vulns)
        medium = [r for r in self.all_results if r.confidence == "MEDIUM"]
        low    = [r for r in self.all_results if r.confidence == "LOW"]

        print(f"{'='*64}")
        print(f"  SUMMARY")
        print(f"  Total probes : {total}")
        print(f"  Vulnerable   : {len(vulns)} ({len(vulns)/max(total,1)*100:.0f}%)")
        print(f"  Safe         : {safe}")

        if not self.llm_judge and (medium or low):
            print(f"\n  ⚠  {len(medium)} MEDIUM + {len(low)} LOW confidence results.")
            print(f"     Re-run with --llm-judge llama3 for better accuracy.")

        # Compare built-in and external datasets when both are present.
        builtin_results  = [r for r in self.all_results if r.attack_module in ATTACK_REGISTRY]
        external_results = [r for r in self.all_results if r.attack_module not in ATTACK_REGISTRY]

        if builtin_results and external_results:
            bv = sum(1 for r in builtin_results  if not r.passed) / max(len(builtin_results), 1) * 100
            ev = sum(1 for r in external_results if not r.passed) / max(len(external_results), 1) * 100
            print(f"\n  Cross-verification:")
            print(f"    Built-in modules   : {bv:.0f}% vulnerable")
            print(f"    External datasets  : {ev:.0f}% vulnerable")
            diff = abs(bv - ev)
            if diff < 10:
                print(f"    Agreement          : ✓ results consistent ({diff:.0f}% difference)")
            else:
                print(f"    Agreement          : ⚠ divergence detected ({diff:.0f}% difference) — review manually")

        print(f"\n  By module:")
        by_module = {}
        for r in self.all_results:
            by_module.setdefault(r.attack_module, []).append(r)
        for mod, results in by_module.items():
            v   = sum(1 for r in results if not r.passed)
            tag = " [ext]" if mod not in ATTACK_REGISTRY else ""
            print(f"    {mod:<24} {v}/{len(results)} vulnerable{tag}")

        print(f"{'='*64}\n")

        for reporter in self.reporters:
            reporter.report(self.all_results)
