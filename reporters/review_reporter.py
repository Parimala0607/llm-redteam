"""Write MEDIUM/LOW results to a review file for manual checking."""

import json
from datetime import datetime
from typing import List
from core.judge import Result


class ReviewReporter:
    """Write MEDIUM/LOW results to a review file, optionally interactively."""

    def __init__(self, path: str, interactive: bool = False):
        self.path = path
        self.interactive = interactive

    def report(self, results: List[Result]):
        flagged = [r for r in results if r.confidence in ("MEDIUM", "LOW")]

        if not flagged:
            print("[review] No MEDIUM/LOW confidence results — nothing to review.")
            return

        print(f"\n[review] {len(flagged)} result(s) need manual verification.")

        if self.interactive:
            confirmed, dismissed = self._interactive_review(flagged)
        else:
            confirmed = []
            dismissed = []

        self._save(flagged, confirmed, dismissed)

    def _interactive_review(self, flagged: List[Result]):
        confirmed = []
        dismissed = []

        print("="*64)
        print("  MANUAL REVIEW MODE")
        print("  For each finding, read the probe + response and decide:")
        print("  [y] Confirmed vulnerability  [n] False positive  [s] Skip")
        print("="*64)

        for i, r in enumerate(flagged, 1):
            print(f"\n[{i}/{len(flagged)}] ── {r.attack_module} / {r.category}")
            print(f"  Score      : {r.score:.2f}  Confidence: {r.confidence}")
            print(f"  Auto reason: {r.reason}")
            print(f"  Matched    : {r.matched or 'none'}")
            print(f"\n  PROBE:")
            print(f"  {r.probe[:300]}")
            print(f"\n  RESPONSE (first 400 chars):")
            # Indent each line so it reads cleanly in the terminal.
            snippet = r.response[:400].replace('\n', '\n  ')
            print(f"  {snippet}")
            print()

            while True:
                try:
                    choice = input("  Verdict [y=confirmed / n=false positive / s=skip]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print("\n[review] Review interrupted.")
                    break

                if choice == "y":
                    note = input("  Note (optional, press Enter to skip): ").strip()
                    confirmed.append({"result": r, "note": note})
                    print("  → Marked as CONFIRMED")
                    break
                elif choice == "n":
                    note = input("  Note (optional, press Enter to skip): ").strip()
                    dismissed.append({"result": r, "note": note})
                    print("  → Marked as FALSE POSITIVE")
                    break
                elif choice == "s":
                    print("  → Skipped")
                    break
                else:
                    print("  Please enter y, n, or s.")

        print(f"\n[review] Review complete:")
        print(f"  Confirmed      : {len(confirmed)}")
        print(f"  False positives: {len(dismissed)}")
        print(f"  Skipped        : {len(flagged) - len(confirmed) - len(dismissed)}")

        return confirmed, dismissed

    def _save(self, flagged, confirmed, dismissed):
        confirmed_probes = {c["result"].probe for c in confirmed}
        dismissed_probes = {d["result"].probe for d in dismissed}

        def verdict(r):
            if r.probe in confirmed_probes:
                return "CONFIRMED"
            if r.probe in dismissed_probes:
                return "FALSE_POSITIVE"
            return "UNREVIEWED"

        def note_for(r):
            for c in confirmed:
                if c["result"].probe == r.probe:
                    return c["note"]
            for d in dismissed:
                if d["result"].probe == r.probe:
                    return d["note"]
            return ""

        data = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_flagged": len(flagged),
            "confirmed": len(confirmed),
            "false_positives": len(dismissed),
            "unreviewed": len(flagged) - len(confirmed) - len(dismissed),
            "findings": [
                {
                    "attack_module": r.attack_module,
                    "category": r.category,
                    "score": round(r.score, 3),
                    "confidence": r.confidence,
                    "auto_reason": r.reason,
                    "matched": r.matched,
                    "verdict": verdict(r),
                    "reviewer_note": note_for(r),
                    "probe": r.probe,
                    "response_snippet": r.response[:500],
                }
                for r in flagged
            ],
        }

        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)

        print(f"[review] Saved → {self.path}")
        if data["confirmed"] > 0:
            print(f"[review] ✓ {data['confirmed']} confirmed finding(s) — include in final report.")
        if data["false_positives"] > 0:
            print(f"[review] ✗ {data['false_positives']} false positive(s) — excluded from final report.")
        if data["unreviewed"] > 0:
            print(f"[review] ⚠  {data['unreviewed']} unreviewed — re-run with --review-interactive to finish.")
