from datetime import datetime


class MarkdownReporter:
    def __init__(self, path: str):
        self.path = path

    def report(self, results):
        total = len(results)
        vulns = [r for r in results if not r.passed]
        safe = total - len(vulns)

        lines = [
            "# LLM Red Team Report",
            f"\n**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"\n## Summary\n",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Total probes | {total} |",
            f"| Vulnerable | {len(vulns)} |",
            f"| Safe | {safe} |",
            f"| Pass rate | {safe/max(total,1)*100:.0f}% |",
            f"\n## Results by Module\n",
        ]

        by_module = {}
        for r in results:
            by_module.setdefault(r.attack_module, []).append(r)

        lines.append("## Module Summary\n")
        lines.append("| Module | Total | Vulnerable | Medium | Low |")
        lines.append("|--------|------:|-----------:|-------:|----:|")
        for mod, mod_results in by_module.items():
            mod_vulns = [r for r in mod_results if not r.passed]
            mod_medium = [r for r in mod_results if r.confidence == "MEDIUM"]
            mod_low = [r for r in mod_results if r.confidence == "LOW"]
            lines.append(
                f"| {mod} | {len(mod_results)} | {len(mod_vulns)} | {len(mod_medium)} | {len(mod_low)} |"
            )
        lines.append("")

        for mod, mod_results in by_module.items():
            mv = [r for r in mod_results if not r.passed]
            lines.append(f"### {mod}")
            lines.append(f"{len(mv)}/{len(mod_results)} vulnerable\n")
            if mv:
                lines.append("| Score | Reason | Probe (truncated) |")
                lines.append("|-------|--------|-------------------|")
                for r in mv:
                    probe_short = r.probe[:80].replace("|", "\\|").replace("\n", " ")
                    lines.append(f"| {r.score:.2f} | {r.reason} | {probe_short}... |")
            lines.append("")

        likely_fp = [r for r in results if r.confidence == "MEDIUM" and not r.passed]
        if likely_fp:
            lines.append("## Likely False Positives / Manual Review\n")
            lines.append("| Module | Score | Reason | Tags | Probe (truncated) |")
            lines.append("|--------|------:|--------|------|-------------------|")
            for r in likely_fp:
                probe_short = r.probe[:90].replace("|", "\\|").replace("\n", " ")
                tags = ", ".join(getattr(r, "tags", [])) or "n/a"
                lines.append(f"| {r.attack_module} | {r.score:.2f} | {r.reason} | {tags} | {probe_short}... |")
            lines.append("")

        if vulns:
            lines.append("## Vulnerable Probe Details\n")
            for i, r in enumerate(vulns, 1):
                lines += [
                    f"### {i}. [{r.attack_module}] Score: {r.score:.2f}",
                    f"**Category:** {r.category}  ",
                    f"**Reason:** {r.reason}  ",
                    f"**Matched:** `{r.matched or 'n/a'}`\n",
                    f"**Tags:** `{', '.join(getattr(r, 'tags', [])) or 'n/a'}`  ",
                    f"**Probe:**",
                    f"```",
                    r.probe,
                    f"```\n",
                    f"**Response (first 400 chars):**",
                    f"```",
                    r.response[:400],
                    f"```\n",
                ]

        with open(self.path, "w") as f:
            f.write("\n".join(lines))
        print(f"[report] Markdown saved → {self.path}")
