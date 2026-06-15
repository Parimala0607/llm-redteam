"""
Dependency CVE Scanner — async/concurrent version.
Queries OSV (Open Source Vulnerabilities) database concurrently
for significant speed improvement over serial scanning.
"""

import json
import urllib.request
import urllib.error
import sys
from dataclasses import dataclass, field
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

OSV_API   = "https://api.osv.dev/v1/query"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"


@dataclass
class CVEFinding:
    package: str
    installed_version: str
    vuln_id: str
    aliases: List[str]
    severity: str
    summary: str
    fixed_version: Optional[str]
    details_url: str


def _query_osv_single(package: str, version: str) -> list:
    payload = json.dumps({
        "package": {"name": package, "ecosystem": "PyPI"},
        "version": version,
    }).encode()
    req = urllib.request.Request(
        OSV_API, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("vulns", [])
    except Exception:
        return []


def _query_osv_batch(pkg_map: dict) -> dict:
    """
    Use OSV batch API — one HTTP call for up to 1000 packages.
    Returns {package_name: [vuln, ...]}
    """
    queries = [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": ver}
        for name, ver in pkg_map.items()
    ]
    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            results = json.loads(r.read()).get("results", [])
        names = list(pkg_map.keys())
        return {
            names[i]: r.get("vulns", [])
            for i, r in enumerate(results)
            if i < len(names)
        }
    except Exception:
        # Batch failed — fall back to concurrent single queries
        return {}


def _extract_severity(vuln: dict) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    found = []
    for sev in vuln.get("severity", []):
        score = sev.get("score", "").upper()
        for level in order:
            if level in score:
                found.append(level)
                break
    for affected in vuln.get("affected", []):
        s = affected.get("database_specific", {}).get("severity", "").upper()
        if s in order:
            found.append(s)
    if not found:
        return "UNKNOWN"
    for level in order:
        if level in found:
            return level
    return "UNKNOWN"


def _extract_fixed_version(vuln: dict, package: str) -> Optional[str]:
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != package.lower():
            continue
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _get_installed_packages() -> dict:
    try:
        import importlib.metadata as meta
        return {
            dist.metadata["Name"].lower(): dist.version
            for dist in meta.distributions()
            if dist.metadata.get("Name")
        }
    except Exception:
        return {}


def _parse_requirements(path: str) -> dict:
    packages = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for op in ["~=", "==", "!=", ">=", "<=", ">", "<"]:
                    if op in line:
                        name, version = line.split(op, 1)
                        packages[name.strip().lower()] = version.strip().split(",")[0]
                        break
    except FileNotFoundError:
        pass
    return packages


def _build_findings(name: str, version: str, vulns: list) -> List[CVEFinding]:
    findings = []
    for vuln in vulns:
        aliases = vuln.get("aliases", [])
        findings.append(CVEFinding(
            package=name,
            installed_version=version,
            vuln_id=vuln.get("id", "UNKNOWN"),
            aliases=aliases,
            severity=_extract_severity(vuln),
            summary=vuln.get("summary", "No summary available"),
            fixed_version=_extract_fixed_version(vuln, name),
            details_url=f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
        ))
    return findings


def scan(
    requirements_file: Optional[str] = None,
    packages: Optional[dict] = None,
    verbose: bool = False,
    concurrency: int = 10,
) -> List[CVEFinding]:
    if packages:
        pkg_map = {k.lower(): v for k, v in packages.items()}
    elif requirements_file:
        pkg_map = _parse_requirements(requirements_file)
    else:
        pkg_map = _get_installed_packages()

    if verbose:
        print(f"[cve] Scanning {len(pkg_map)} packages (batch API + {concurrency} workers fallback)...")

    import time
    t0 = time.time()

    # Try batch first (single HTTP call)
    batch_results = _query_osv_batch(pkg_map)

    findings: List[CVEFinding] = []

    if batch_results:
        # Batch succeeded
        for name, version in pkg_map.items():
            vulns = batch_results.get(name, [])
            pkg_findings = _build_findings(name, version, vulns)
            findings.extend(pkg_findings)
            if verbose and pkg_findings:
                for f in pkg_findings:
                    cve = next((a for a in f.aliases if a.startswith("CVE-")), f.vuln_id)
                    print(f"  [{f.severity:<8}] {name}=={version} → {cve}")
    else:
        # Fallback: concurrent single queries
        if verbose:
            print(f"[cve] Batch API unavailable — using {concurrency} concurrent queries...")

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            future_map = {
                pool.submit(_query_osv_single, name, ver): (name, ver)
                for name, ver in pkg_map.items()
            }
            for future in as_completed(future_map):
                name, version = future_map[future]
                try:
                    vulns = future.result()
                    pkg_findings = _build_findings(name, version, vulns)
                    findings.extend(pkg_findings)
                    if verbose and pkg_findings:
                        for f in pkg_findings:
                            cve = next((a for a in f.aliases if a.startswith("CVE-")), f.vuln_id)
                            print(f"  [{f.severity:<8}] {name}=={version} → {cve}")
                except Exception as e:
                    print(f"[cve] warn: scan failed for {name}=={version}: {e}", file=sys.stderr)

    elapsed = time.time() - t0
    if verbose:
        print(f"[cve] Scan complete in {elapsed:.2f}s")

    return findings


def print_report(findings: List[CVEFinding]):
    if not findings:
        print("[cve] No known vulnerabilities found.\n")
        return
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    by_sev = {s: [] for s in order}
    for f in findings:
        by_sev.get(f.severity, by_sev["UNKNOWN"]).append(f)
    counts = {s: len(v) for s, v in by_sev.items() if v}
    print(f"\n[cve] {len(findings)} vulnerabilities: " +
          ", ".join(f"{s}: {n}" for s, n in counts.items()))
    print()
    for sev in order:
        for f in by_sev[sev]:
            cve_str = ", ".join(a for a in f.aliases if a.startswith("CVE-")) or f.vuln_id
            fixed   = f"→ fix: {f.fixed_version}" if f.fixed_version else "→ no fix available"
            print(f"  [{f.severity:<8}] {f.package}=={f.installed_version}")
            print(f"             {cve_str}")
            print(f"             {f.summary[:100]}")
            print(f"             {fixed}")
            print(f"             {f.details_url}\n")


def save_json(findings: List[CVEFinding], path: str):
    data = {
        "total": len(findings),
        "findings": [
            {
                "package": f.package, "installed_version": f.installed_version,
                "vuln_id": f.vuln_id, "aliases": f.aliases,
                "severity": f.severity, "summary": f.summary,
                "fixed_version": f.fixed_version, "details_url": f.details_url,
            }
            for f in findings
        ],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"[cve] JSON saved → {path}")
