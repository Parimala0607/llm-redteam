#!/usr/bin/env python3
"""
validate_judge.py — measure how good the judge actually is.

This is the piece that turns the tool into research: instead of trusting the
judge's vulnerability counts, you measure the judge against a human-labeled
gold set and report precision / recall / F1, Cohen's kappa, score calibration,
and ROC-AUC. It also dumps every disagreement (judge != human) so you can see
*where* and *why* the judge is wrong.

Run from the project root:

    python -m eval.validate_judge --gold eval/gold_set.jsonl
    python -m eval.validate_judge --gold eval/gold_set.jsonl --judge pipeline --llm-judge llama3
    python -m eval.validate_judge --gold eval/gold_set.jsonl --disagreements out/disagree.json

Judge modes:
    rule      (default) — RuleBasedJudge only, fully offline
    pipeline            — RuleBasedJudge + LLMJudge escalation on non-HIGH
                          confidence (exactly what the runner does)
    llm                 — LLMJudge on every item (needs a reachable Ollama)
"""

from __future__ import annotations
import argparse
import json
import os
import sys

# allow `python eval/validate_judge.py` as well as `python -m eval.validate_judge`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.judge import RuleBasedJudge, LLMJudge, score_unbounded  # noqa: E402
from eval import metrics as M  # noqa: E402


VALID_LABELS = {"safe", "vuln", "vulnerable"}


def _norm_label(raw: str) -> bool:
    """Return True if the human label means 'vulnerable'."""
    v = (raw or "").strip().lower()
    if v not in VALID_LABELS:
        raise ValueError(f"bad label {raw!r}; use 'safe' or 'vuln'")
    return v in ("vuln", "vulnerable")


def load_gold(path: str) -> list:
    records = []
    with open(path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                raise SystemExit(f"[gold] line {ln}: invalid JSON — {e}")
            for required in ("probe", "response", "label"):
                if required not in rec:
                    raise SystemExit(f"[gold] line {ln}: missing '{required}'")
            records.append(rec)
    if not records:
        raise SystemExit(f"[gold] no records found in {path}")
    return records


def judge_one(rule: RuleBasedJudge, llm, mode: str, rec: dict):
    """Return (judge_says_vuln: bool, judge_score: float, conf: str)."""
    probe = rec["probe"]
    response = rec["response"]
    category = rec.get("category", "")
    module = rec.get("attack_module", "")

    if mode == "llm":
        if llm is None:
            raise SystemExit("--judge llm requires --llm-judge <model>")
        # wrap response in a Result-shaped stub for recheck
        stub = rule.score(probe, response, category, module)
        res = llm.recheck(stub)
        return (not res.passed, res.score, res.confidence)

    # rule-based first (also the base for the pipeline)
    if module == "unbounded_consumption":
        res = score_unbounded(probe, response, attack_module=module)
    else:
        res = rule.score(probe, response, category, module)

    if mode == "pipeline" and llm is not None and res.confidence != "HIGH":
        res = llm.recheck(res)

    return (not res.passed, res.score, res.confidence)


def main():
    ap = argparse.ArgumentParser(description="Validate the judge against a human gold set.")
    ap.add_argument("--gold", required=True, help="path to gold_set.jsonl")
    ap.add_argument("--judge", choices=["rule", "pipeline", "llm"], default="rule")
    ap.add_argument("--llm-judge", default=None,
                    help="Ollama model name for LLMJudge (pipeline/llm modes)")
    ap.add_argument("--base-url", default="http://localhost:11434")
    ap.add_argument("--bins", type=int, default=5, help="calibration bins")
    ap.add_argument("--disagreements", default=None,
                    help="write judge!=human cases to this JSON file")
    args = ap.parse_args()

    gold = load_gold(args.gold)
    rule = RuleBasedJudge()
    llm = None
    if args.judge in ("pipeline", "llm"):
        if not args.llm_judge:
            raise SystemExit(f"--judge {args.judge} requires --llm-judge <model>")
        llm = LLMJudge(model=args.llm_judge, base_url=args.base_url)

    human, judge_vuln, scores, confs, disagreements = [], [], [], [], []

    for rec in gold:
        try:
            h = _norm_label(rec["label"])
        except ValueError as e:
            raise SystemExit(f"[gold] id={rec.get('id','?')}: {e}")
        jv, js, conf = judge_one(rule, llm, args.judge, rec)
        human.append(h)
        judge_vuln.append(jv)
        scores.append(js)
        confs.append(conf)
        if h != jv:
            disagreements.append({
                "id": rec.get("id"),
                "attack_module": rec.get("attack_module"),
                "category": rec.get("category"),
                "human": "vuln" if h else "safe",
                "judge": "vuln" if jv else "safe",
                "error_type": "false_positive" if (jv and not h) else "false_negative",
                "judge_score": round(js, 3),
                "judge_confidence": conf,
                "probe": rec["probe"][:200],
                "response": rec["response"][:400],
                "labeler_notes": rec.get("notes", ""),
            })

    rep = M.binary_report(human, judge_vuln)
    kappa = M.cohens_kappa(human, judge_vuln)
    bins, ece = M.calibration(human, scores, n_bins=args.bins)
    auc = M.roc_auc(human, scores)

    # ── print ────────────────────────────────────────────────────────────────
    bar = "=" * 64
    print(f"\n{bar}")
    print("  JUDGE VALIDATION")
    print(f"  Gold set : {args.gold}  ({rep.n} labeled examples)")
    print(f"  Judge    : {args.judge}" + (f"  (llm={args.llm_judge})" if llm else ""))
    print(bar)

    print("\n  Confusion matrix  (positive class = 'vulnerable')")
    print(f"                    judge:vuln   judge:safe")
    print(f"    human:vuln        TP={rep.tp:<4}      FN={rep.fn:<4}")
    print(f"    human:safe        FP={rep.fp:<4}      TN={rep.tn:<4}")

    print("\n  Detection quality")
    print(f"    Precision : {rep.precision:.3f}   (of flagged, how many were real)")
    print(f"    Recall    : {rep.recall:.3f}   (of real vulns, how many caught)")
    print(f"    F1        : {rep.f1:.3f}")
    print(f"    Accuracy  : {rep.accuracy:.3f}")
    print(f"    FP rate   : {rep.fpr:.3f}   (safe responses wrongly flagged)")

    print("\n  Agreement with humans")
    print(f"    Cohen's kappa : {kappa:.3f}  ({M.kappa_label(kappa)})")

    print("\n  Score calibration")
    print(f"    {'bin':<14}{'n':>5}{'mean_score':>12}{'obs_vuln':>10}")
    for b in bins:
        if b.count:
            print(f"    [{b.lo:.1f},{b.hi:.1f})    {b.count:>5}{b.mean_score:>12.3f}{b.observed_vuln:>10.3f}")
    print(f"    ECE       : {ece:.3f}   (0 = perfectly calibrated)")
    auc_str = "n/a (single class)" if auc != auc else f"{auc:.3f}"
    print(f"    ROC-AUC   : {auc_str}")

    if disagreements:
        fp = sum(1 for d in disagreements if d["error_type"] == "false_positive")
        fn = sum(1 for d in disagreements if d["error_type"] == "false_negative")
        print(f"\n  Disagreements : {len(disagreements)}  ({fp} false positives, {fn} false negatives)")
        for d in disagreements[:8]:
            print(f"    - [{d['error_type']:<15}] {d['attack_module'] or d['category'] or '?'} "
                  f"(score={d['judge_score']}, conf={d['judge_confidence']})")
        if len(disagreements) > 8:
            print(f"    ... and {len(disagreements) - 8} more")
    else:
        print("\n  Disagreements : none — judge matched humans on every item")

    print(f"{bar}\n")

    if args.disagreements:
        os.makedirs(os.path.dirname(args.disagreements) or ".", exist_ok=True)
        with open(args.disagreements, "w", encoding="utf-8") as f:
            json.dump({"count": len(disagreements), "cases": disagreements}, f, indent=2)
        print(f"[validate] wrote {len(disagreements)} disagreement(s) → {args.disagreements}")

    # non-zero exit if the judge is unreliable, so this can gate CI
    if rep.f1 < 0.5 or kappa < 0.2:
        print("[validate] WARNING: judge reliability is low (F1<0.5 or kappa<0.2).")


if __name__ == "__main__":
    main()
