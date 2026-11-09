import json

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

def load_findings(path):
    with open(path, encoding="utf-8") as f:
        return parse_report(json.load(f))


def parse_report(report):
    artifact = report.get("ArtifactName", "unknown")
    findings = []

    for result in report.get("Results") or []:
        target = result.get("Target", "")

        for v in result.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion") or "none available"
            findings.append({
                "kind": "vulnerability",
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

        for m in result.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            findings.append({
                "kind": "misconfiguration",
                "id": m.get("ID", ""),
                "severity": m.get("Severity", "UNKNOWN"),
                "text": (
                    f"Check: {m.get('ID')} {m.get('Title')}\n"
                    f"Severity: {m.get('Severity')}\n"
                    f"Target: {target}\n"
                    f"Message: {m.get('Message')}\n"
                    f"Resolution: {m.get('Resolution')}"
                ),
            })

        for s in result.get("Secrets") or []:
            findings.append({
                "kind": "secret",
                "id": s.get("RuleID", ""),
                "severity": s.get("Severity", "UNKNOWN"),
                "text": (
                    f"Secret rule: {s.get('RuleID')} ({s.get('Category')})\n"
                    f"Title: {s.get('Title')}\n"
                    f"Severity: {s.get('Severity')}\n"
                    f"Target: {target}, line {s.get('StartLine')}\n"
                    f"Match: {s.get('Match')}"
                ),
            })

    return sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 4))