import json

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def load_findings(path):
    with open(path, encoding="utf-8") as f:
        report = json.load(f)

    artifact = report.get("ArtifactName", "unknown")
    findings = []

    for result in report.get("Results") or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion") or "none available"
            findings.append({
                "id": v.get("VulnerabilityID", ""),
                "severity": v.get("Severity", "UNKNOWN"),
                "text": (
                    f"Package: {v.get('PkgName')} {v.get('InstalledVersion')}\n"
                    f"Vulnerability: {v.get('VulnerabilityID')}\n"
                    f"Severity: {v.get('Severity')}\n"
                    f"Status: {v.get('Status', 'unknown')}\n"
                    f"Fixed version: {fixed}\n"
                    f"Title: {v.get('Title', '')}\n"
                    f"Target: {target} (artifact: {artifact})"
                ),
            })

    return sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 4))