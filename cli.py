#!/usr/bin/env python3
"""
LLM Red Teaming CLI

Commands:
  run        Run behavioral red team probes against a target model
  scan-cve   Scan Python dependencies for known CVEs (via OSV database)
  compare    Compare results across tools (Garak, promptfoo, HarmBench)
  list       List available attack modules and OWASP coverage
  cache      Manage probe result cache
"""

import argparse
import sys
from attacks import ATTACK_REGISTRY
from reporters.console import ConsoleReporter
from reporters.json_reporter import JsonReporter
from reporters.markdown_reporter import MarkdownReporter
from reporters.review_reporter import ReviewReporter


def cmd_run(args):
    from core.target import build_target
    from core.async_runner import AsyncRunner

    target = build_target(args.target, base_url=args.base_url)

    if args.attacks == "all":
        selected = list(ATTACK_REGISTRY.keys())
    else:
        selected = [a.strip() for a in args.attacks.split(",")]
        unknown  = [a for a in selected if a not in ATTACK_REGISTRY]
        if unknown:
            print(f"[error] Unknown modules: {unknown}")
            print(f"Available: {list(ATTACK_REGISTRY.keys())}")
            sys.exit(1)

    # External datasets
    from attacks.external import HarmBenchAttack, JailbreakBenchAttack, GarakAttack
    dynamic = {}
    if args.harmbench:
        try:
            hb = HarmBenchAttack(args.harmbench)
            dynamic["harmbench"] = hb
            print(f"[external] HarmBench: {len(hb._prompts)} probes")
        except FileNotFoundError as e:
            print(f"[error] {e}"); sys.exit(1)
    if args.jailbreakbench:
        try:
            jb = JailbreakBenchAttack(args.jailbreakbench)
            dynamic["jailbreakbench"] = jb
            print(f"[external] JailbreakBench: {len(jb._prompts)} probes")
        except FileNotFoundError as e:
            print(f"[error] {e}"); sys.exit(1)
    if args.garak:
        try:
            gk = GarakAttack()
            dynamic["garak"] = gk
            print(f"[external] Garak: {len(gk._prompts)} probes")
        except (ImportError, RuntimeError) as e:
            print(f"[error] {e}"); sys.exit(1)

    # Reporters
    reporters = [ConsoleReporter()]
    live_reporters = []
    if args.output_json:
        json_reporter = JsonReporter(args.output_json)
        reporters.append(json_reporter)
        if args.live_report:
            live_reporters.append(json_reporter)
    if args.output_md:
        md_reporter = MarkdownReporter(args.output_md)
        reporters.append(md_reporter)
        if args.live_report:
            live_reporters.append(md_reporter)
    if args.review:
        reporters.append(ReviewReporter(args.review, interactive=False))
    if args.review_interactive:
        reporters.append(ReviewReporter(args.review_interactive, interactive=True))

    runner = AsyncRunner(
        target=target,
        attack_names=selected,
        dynamic_modules=dynamic,
        max_probes=args.max_probes,
        reporters=reporters,
        verbose=args.verbose,
        llm_judge_model=args.llm_judge,
        concurrency=args.concurrency,
        use_cache=not args.no_cache,
        live_reporters=live_reporters,
    )
    runner.run()


def cmd_scan_cve(args):
    from core.cve_scanner import scan, print_report, save_json
    findings = scan(requirements_file=args.requirements, verbose=True)
    print_report(findings)
    if args.output_json:
        save_json(findings, args.output_json)
    if args.fail_on:
        levels    = [l.strip().upper() for l in args.fail_on.split(",")]
        triggered = [f for f in findings if f.severity in levels]
        if triggered:
            print(f"[cve] {len(triggered)} {args.fail_on} findings → exit 1")
            sys.exit(1)


def cmd_compare(args):
    from core.compare import (
        load_your_results, load_garak_results,
        load_promptfoo_results, load_harmbench_results,
        print_comparison, save_comparison_json,
    )
    tool_results = []
    if args.your_results:
        tool_results.append(load_your_results(args.your_results))
    if args.garak:
        tool_results.append(load_garak_results(args.garak))
    if args.promptfoo:
        tool_results.append(load_promptfoo_results(args.promptfoo))
    if args.harmbench:
        tool_results.append(load_harmbench_results(args.harmbench))

    if not tool_results:
        print("[compare] Provide at least one result file. See --help.")
        sys.exit(1)

    print_comparison(tool_results)
    if args.output_json:
        save_comparison_json(tool_results, args.output_json)


def cmd_cache(args):
    from core.cache import ProbeCache
    cache = ProbeCache()
    if args.clear:
        cache.clear()
    else:
        stats = cache.stats()
        print(f"[cache] {stats['entries']} entries in {stats['file']}")


def cmd_list(args):
    from attacks import OWASP_COVERAGE
    print("\nBuilt-in attack modules:\n")
    total = 0
    for name, cls in ATTACK_REGISTRY.items():
        count = len(cls().probes())
        total += count
        print(f"  {name:<28} {count:>3} probes  — {cls.description}")
    print(f"\n  Total: {total} probes across {len(ATTACK_REGISTRY)} modules")

    print("\nOWASP LLM Top 10 Coverage:\n")
    covered = sum(1 for v in OWASP_COVERAGE.values() if v)
    for owasp, modules in OWASP_COVERAGE.items():
        status = "✅" if modules else "❌"
        mods   = ", ".join(modules) if modules else "not covered (deployment-specific)"
        print(f"  {status} {owasp}")
        print(f"       → {mods}")
    print(f"\n  Coverage: {covered}/10\n")

    print("External dataset flags (cross-verification):")
    print("  --harmbench <csv>         HarmBench (400 probes)")
    print("  --jailbreakbench <json>   JailbreakBench (100 probes)")
    print("  --garak                   Garak probes (pip install garak)\n")


def main():
    parser = argparse.ArgumentParser(
        prog="redteam",
        description="LLM Red Teaming CLI — OWASP LLM Top 10 coverage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # ── run ──────────────────────────────────────────────────────────────────
    run_p = sub.add_parser("run", help="Run red team probes against a target model")
    run_p.add_argument("--target", required=True,
        help="e.g. ollama/llama3 | hf/mistralai/Mistral-7B | openai-compat/model")
    run_p.add_argument("--base-url",    default=None)
    run_p.add_argument("--attacks",     default="all",
        help=f"Comma-separated or 'all'. Modules: {', '.join(ATTACK_REGISTRY.keys())}")
    run_p.add_argument("--max-probes",  type=int, default=None)
    run_p.add_argument("--concurrency", type=int, default=1,
        help="Parallel probe workers (default: 1 for CPU; try 2-4 if GPU)")
    run_p.add_argument("--no-cache",    action="store_true",
        help="Disable probe result caching")
    run_p.add_argument("--output-json", default=None, metavar="FILE")
    run_p.add_argument("--output-md",   default=None, metavar="FILE")
    run_p.add_argument("--live-report", action="store_true",
        help="Write JSON/Markdown snapshots after each module finishes")
    run_p.add_argument("-v", "--verbose", action="store_true")
    run_p.add_argument("--llm-judge",  default=None, metavar="MODEL",
        help="Ollama model for secondary judging of ambiguous results")
    run_p.add_argument("--review",             default=None, metavar="FILE")
    run_p.add_argument("--review-interactive", default=None, metavar="FILE")
    run_p.add_argument("--harmbench",      default=None, metavar="CSV")
    run_p.add_argument("--jailbreakbench", default=None, metavar="JSON")
    run_p.add_argument("--garak",          action="store_true")

    # ── scan-cve ─────────────────────────────────────────────────────────────
    cve_p = sub.add_parser("scan-cve", help="Scan dependencies for CVEs (OSV database)")
    cve_p.add_argument("--requirements", default=None, metavar="FILE")
    cve_p.add_argument("--output-json",  default=None, metavar="FILE")
    cve_p.add_argument("--fail-on",      default=None, metavar="SEVERITY",
        help="Exit 1 on findings at this severity. e.g. CRITICAL,HIGH")

    # ── compare ──────────────────────────────────────────────────────────────
    cmp_p = sub.add_parser("compare", help="Compare results across tools")
    cmp_p.add_argument("--your-results", default=None, metavar="JSON",
        help="Your tool's results.json (from --output-json)")
    cmp_p.add_argument("--garak",      default=None, metavar="JSONL",
        help="Garak hitlog .jsonl file")
    cmp_p.add_argument("--promptfoo",  default=None, metavar="JSON",
        help="promptfoo results.json")
    cmp_p.add_argument("--harmbench",  default=None, metavar="JSON",
        help="HarmBench evaluation output JSON")
    cmp_p.add_argument("--output-json", default=None, metavar="FILE")

    # ── cache ─────────────────────────────────────────────────────────────────
    cac_p = sub.add_parser("cache", help="Manage probe result cache")
    cac_p.add_argument("--clear", action="store_true", help="Clear all cached results")

    # ── list ─────────────────────────────────────────────────────────────────
    sub.add_parser("list", help="List modules and OWASP coverage")

    args = parser.parse_args()

    if args.command == "run":          cmd_run(args)
    elif args.command == "scan-cve":   cmd_scan_cve(args)
    elif args.command == "compare":    cmd_compare(args)
    elif args.command == "cache":      cmd_cache(args)
    elif args.command == "list":       cmd_list(args)
    else:                              parser.print_help()


if __name__ == "__main__":
    main()
