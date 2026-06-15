#!/usr/bin/env python3
"""
label.py — build / extend the human gold set used by validate_judge.py.

Workflow:
  1. Run the tool and save full results (see note below on full responses).
  2. Feed that results file in here; label each (probe, response) pair by hand.
  3. Labels append to gold_set.jsonl. Already-labeled items are skipped, so you
     can stop and resume anytime.

    python -m eval.label --from results.json --gold eval/gold_set.jsonl
    python -m eval.label --from .redteam_cache.json --cache --gold eval/gold_set.jsonl

IMPORTANT — full responses:
  The JSON reporter only stores a 300-char `response_snippet`. For rigorous
  labeling you want the *full* text the judge saw. The probe cache
  (.redteam_cache.json) stores full responses — pass --cache to read from it.
  Alternatively, extend JsonReporter to emit a full `response` field.

SAFETY:
  Responses you label may contain harmful model output. This tool writes a
  `response` field to the gold set verbatim so the judge sees what it saw.
  If you intend to share the gold set, run with --redact to store a structural
  placeholder for any item you label 'vuln' (keeps list/step structure markers,
  drops the operational text). Redacted items still exercise the judge's
  pattern logic but are safe to publish.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import sys


def _id(probe: str, response: str) -> str:
    return hashlib.sha1((probe + "\x00" + response).encode("utf-8")).hexdigest()[:12]


def _load_existing_ids(gold_path: str) -> set:
    ids = set()
    if os.path.exists(gold_path):
        with open(gold_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ids.add(json.loads(line).get("id"))
                except json.JSONDecodeError:
                    pass
    return ids


def _items_from_results(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for r in data.get("results", []):
        resp = r.get("response") or r.get("response_snippet", "")
        out.append({
            "probe": r.get("probe", ""),
            "response": resp,
            "attack_module": r.get("attack_module", ""),
            "category": r.get("category", ""),
            "judge_guess": "vuln" if not r.get("passed", True) else "safe",
        })
    return out


def _items_from_cache(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for entry in data.values():
        out.append({
            "probe": entry.get("probe", ""),
            "response": entry.get("response", ""),
            "attack_module": entry.get("attack_module", ""),
            "category": entry.get("category", ""),
            "judge_guess": "vuln" if not entry.get("passed", True) else "safe",
        })
    return out


def _redact(response: str) -> str:
    """Keep structural markers (lists / code fences) the judge keys on; drop content."""
    lines = response.splitlines()
    kept = []
    for ln in lines:
        if re.match(r"^\s*(\d+[\.\)]|[-*•]|step\s+\d+)", ln, re.IGNORECASE):
            marker = re.match(r"^\s*(\d+[\.\)]|[-*•]|step\s+\d+)", ln, re.IGNORECASE).group(0)
            kept.append(f"{marker} [REDACTED]")
        elif ln.strip().startswith("```"):
            kept.append("```\n[REDACTED]\n```")
    if not kept:
        kept = ["[REDACTED — model complied; content withheld]"]
    return "\n".join(kept)


def main():
    ap = argparse.ArgumentParser(description="Hand-label responses into a gold set.")
    ap.add_argument("--from", dest="src", required=True, help="results.json or cache file")
    ap.add_argument("--cache", action="store_true", help="source is a .redteam_cache.json file")
    ap.add_argument("--gold", default="eval/gold_set.jsonl")
    ap.add_argument("--labeler", default=os.environ.get("USER", "anon"))
    ap.add_argument("--redact", action="store_true",
                    help="store structural placeholder for items labeled 'vuln'")
    args = ap.parse_args()

    items = _items_from_cache(args.src) if args.cache else _items_from_results(args.src)
    existing = _load_existing_ids(args.gold)

    todo = []
    for it in items:
        if not it["probe"] or not it["response"]:
            continue
        it["id"] = _id(it["probe"], it["response"])
        if it["id"] not in existing:
            todo.append(it)

    if not todo:
        print("[label] nothing new to label — all items already in the gold set.")
        return

    print("=" * 64)
    print(f"  LABELING  ({len(todo)} new items)   labeler={args.labeler}")
    print("  For each item: [v] vulnerable  [s] safe  [k] skip  [q] quit & save")
    print("  (the judge's own guess is shown only after you decide, to avoid bias)")
    print("=" * 64)

    os.makedirs(os.path.dirname(args.gold) or ".", exist_ok=True)
    written = 0
    with open(args.gold, "a", encoding="utf-8") as out:
        for i, it in enumerate(todo, 1):
            print(f"\n--- [{i}/{len(todo)}] module={it['attack_module']} cat={it['category']}")
            print(f"PROBE:\n  {it['probe'][:500]}")
            print(f"RESPONSE:\n  {it['response'][:1200]}")
            choice = ""
            while choice not in ("v", "s", "k", "q"):
                choice = input("  label [v/s/k/q]: ").strip().lower()
            if choice == "q":
                break
            if choice == "k":
                continue

            label = "vuln" if choice == "v" else "safe"
            print(f"    (judge guessed: {it['judge_guess']})")
            note = input("  optional note: ").strip()

            stored_response = it["response"]
            if args.redact and label == "vuln":
                stored_response = _redact(it["response"])

            rec = {
                "id": it["id"],
                "probe": it["probe"],
                "response": stored_response,
                "attack_module": it["attack_module"],
                "category": it["category"],
                "label": label,
                "labeler": args.labeler,
                "notes": note,
                "redacted": bool(args.redact and label == "vuln"),
            }
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out.flush()
            written += 1

    print(f"\n[label] wrote {written} new label(s) → {args.gold}")


if __name__ == "__main__":
    main()
