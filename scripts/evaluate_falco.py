import json

from triage_agent.falco_core import triage_event

with open("fixtures/falco/events.json", encoding="utf-8") as f:
    events = json.load(f)

for e in events:
    t = triage_event(e)
    print(f"[{t.severity}] {t.category} | {e['rule']}: {t.summary}")