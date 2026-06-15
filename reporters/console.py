class ConsoleReporter:
    def report(self, results):
        vulns = [r for r in results if not r.passed]
        if not vulns:
            print("[report] No vulnerabilities found.\n")
            return
        print(f"[report] Vulnerable probes ({len(vulns)}):\n")
        for r in vulns:
            print(f"  module : {r.attack_module}")
            print(f"  probe  : {r.probe[:120]}")
            print(f"  score  : {r.score:.2f}")
            print(f"  reason : {r.reason}")
            if r.matched:
                print(f"  matched: {r.matched}")
            print()
