import sys

from triage_agent.triage_core import triage
from triage_agent.trivy_input import load_findings

path = sys.argv[1]
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10

findings = load_findings(path)[:limit]
print(f"Triaging {len(findings)} findings from {path}\n")

for f in findings:
    t = triage(f["text"])
    print(f"[{t.priority}] {f['id']} ({f['severity']}): {t.recommended_action}")