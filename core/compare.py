"""
Compare command — side-by-side comparison of your tool's results
against Garak, promptfoo, or HarmBench evaluation outputs.
"""

import json
import os
from typing import Optional


def load_your_results(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    total    = data.get("total", 0)
    vuln     = data.get("vulnerable", 0)
    by_mod   = {}
    for r in data.get("results", []):
        mod = r.get("attack_module", "unknown")
        by_mod.setdefault(mod, {"total": 0, "vuln": 0})
        by_mod[mod]["total"] += 1
        if not r.get("passed", True):
            by_mod[mod]["vuln"] += 1
    return {
        "tool": "your_tool",
        "total": total,
        "vulnerable": vuln,
        "pass_rate": round((total - vuln) / max(total, 1) * 100, 1),
        "asr": round(vuln / max(total, 1) * 100, 1),  # attack success rate
        "by_module": by_mod,
    }


def load_garak_results(path: str) -> dict:
    """
    Parse Garak's JSONL hit file (garak generates .hitlog.jsonl).
    Each line: {"probe": "...", "detector": "...", "passed": true/false}
    """
    total = vuln = 0
    by_mod = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                probe_class = r.get("probe", r.get("probe_classname", "unknown"))
                mod = probe_class.split(".")[0] if "." in probe_class else probe_class
                by_mod.setdefault(mod, {"total": 0, "vuln": 0})
                total += 1
                by_mod[mod]["total"] += 1
                if not r.get("passed", True):
                    vuln += 1
                    by_mod[mod]["vuln"] += 1
    except FileNotFoundError:
        return {"tool": "garak", "error": f"File not found: {path}"}

    return {
        "tool": "garak",
        "total": total,
        "vulnerable": vuln,
        "pass_rate": round((total - vuln) / max(total, 1) * 100, 1),
        "asr": round(vuln / max(total, 1) * 100, 1),
        "by_module": by_mod,
    }


def load_promptfoo_results(path: str) -> dict:
    """
    Parse promptfoo's JSON output.
    promptfoo redteam generates results.json with 'results' array.
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"tool": "promptfoo", "error": f"File not found: {path}"}

    results = data.get("results", data if isinstance(data, list) else [])
    total = vuln = 0
    by_mod = {}

    for r in results:
        plugin = r.get("metadata", {}).get("pluginId", r.get("plugin", "unknown"))
        by_mod.setdefault(plugin, {"total": 0, "vuln": 0})
        total += 1
        by_mod[plugin]["total"] += 1
        # promptfoo uses success=True to mean the attack worked.
        if r.get("success", False) or not r.get("pass", True):
            vuln += 1
            by_mod[plugin]["vuln"] += 1

    return {
        "tool": "promptfoo",
        "total": total,
        "vulnerable": vuln,
        "pass_rate": round((total - vuln) / max(total, 1) * 100, 1),
        "asr": round(vuln / max(total, 1) * 100, 1),
        "by_module": by_mod,
    }


def load_harmbench_results(path: str) -> dict:
    """
    Parse HarmBench evaluation output JSON.
    HarmBench eval script outputs: {"results": [{"behavior": "...", "passed": bool}]}
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"tool": "harmbench", "error": f"File not found: {path}"}

    results = data.get("results", [])
    total   = len(results)
    vuln    = sum(1 for r in results if not r.get("passed", True))

    return {
        "tool": "harmbench",
        "total": total,
        "vulnerable": vuln,
        "pass_rate": round((total - vuln) / max(total, 1) * 100, 1),
        "asr": round(vuln / max(total, 1) * 100, 1),
        "by_module": {},
    }


def print_comparison(tool_results: list):
    """Print a side-by-side comparison table."""
    valid = [t for t in tool_results if "error" not in t]
    errors = [t for t in tool_results if "error" in t]

    if errors:
        for e in errors:
            print(f"[compare] ⚠ {e['tool']}: {e['error']}")

    if not valid:
        print("[compare] No valid results to compare.")
        return

    print(f"\n{'='*66}")
    print(f"  CROSS-TOOL COMPARISON")
    print(f"{'='*66}")

    # Header.
    col_w = 14
    header = f"  {'Metric':<22}" + "".join(f"{t['tool']:<{col_w}}" for t in valid)
    print(header)
    print("  " + "-" * (22 + col_w * len(valid)))

    # Rows.
    rows = [
        ("Total probes",  lambda t: str(t["total"])),
        ("Vulnerable",    lambda t: str(t["vulnerable"])),
        ("ASR %",         lambda t: f"{t['asr']}%"),
        ("Pass rate %",   lambda t: f"{t['pass_rate']}%"),
    ]
    for label, fn in rows:
        row = f"  {label:<22}" + "".join(f"{fn(t):<{col_w}}" for t in valid)
        print(row)

    # Agreement check.
    if len(valid) >= 2:
        asrs = [t["asr"] for t in valid]
        min_asr, max_asr = min(asrs), max(asrs)
        spread = max_asr - min_asr
        print(f"\n  ASR spread across tools: {spread:.1f}%")
        if spread < 10:
            print(f"  Agreement: ✓ GOOD — tools are consistent (< 10% spread)")
        elif spread < 25:
            print(f"  Agreement: ⚠ MODERATE — some divergence, review MEDIUM confidence results")
        else:
            print(f"  Agreement: ✗ HIGH DIVERGENCE — judge calibration may need tuning")

        # Find the strictest and most lenient tools.
        strictest = min(valid, key=lambda t: t["asr"])
        lenienth  = max(valid, key=lambda t: t["asr"])
        print(f"  Most conservative: {strictest['tool']} ({strictest['asr']}% ASR)")
        print(f"  Most aggressive  : {lenienth['tool']} ({lenienth['asr']}% ASR)")

    print(f"{'='*66}\n")


def save_comparison_json(tool_results: list, path: str):
    with open(path, "w") as f:
        json.dump({"comparison": tool_results}, f, indent=2)
    print(f"[compare] Saved → {path}")
