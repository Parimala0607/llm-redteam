import json
from datetime import datetime


class JsonReporter:
    def __init__(self, path: str):
        self.path = path

    def report(self, results):
        data = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total": len(results),
            "vulnerable": sum(1 for r in results if not r.passed),
            "safe": sum(1 for r in results if r.passed),
            "results": [
                {
                    "attack_module": r.attack_module,
                    "category": r.category,
                    "passed": r.passed,
                    "score": round(r.score, 3),
                    "confidence": r.confidence,
                    "reason": r.reason,
                    "matched": r.matched,
                    "tags": getattr(r, "tags", []),
                    "probe": r.probe,
                    "response_snippet": r.response[:300],
                }
                for r in results
            ],
        }
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[report] JSON saved → {self.path}")
