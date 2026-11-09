import json

from triage_agent.graph import app, run
from triage_agent.trivy_input import load_findings

trivy = load_findings("fixtures/trivy/sample_nginx.json")[:2]
with open("fixtures/falco/events.json", encoding="utf-8") as f:
    falco = json.load(f)[:2]

for item in trivy + falco:
    result = run(item)
    label = item.get("id") or item.get("rule")
    print(f"{type(result).__name__} | {label} | {result.category}")

print()
print(app.get_graph().draw_mermaid())