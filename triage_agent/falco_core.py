import json
import os

from langchain_openai import ChatOpenAI
from schema import RuntimeTriage

runtime_triager = ChatOpenAI(
    model=os.environ["LLM_MODEL"],
    base_url=os.environ["LLM_BASE_URL"],
    api_key=os.environ["LLM_API_KEY"],
    temperature=0,
    max_retries=5,
).with_structured_output(RuntimeTriage)

FALCO_PROMPT = """You triage one runtime alert from a container, in Falco's JSON format. One alert at a time.

Categories:
- suspicious: behavior that suggests compromise, such as a shell spawned by an application process, a download piped into a shell, writes to system files, access to sensitive files, or a connection to an unexpected destination.
- benign: normal activity with a plausible legitimate explanation in the evidence, such as a package install inside a CI build container.

Severity:
- Do not copy Falco's own priority label (for example "Notice") into severity. Rate by potential impact and evidence of compromise.
- critical: active compromise or remote code execution is evident.
- high: strong indicators of compromise.
- medium: an unexplained event with limited evidence of harm.
- low: minor, and all benign events.

Rules:
- Use only the evidence given. Do not invent details.
- If the evidence supports a legitimate explanation, choose benign.
- Context fields (user, container, namespace, parent process) count as evidence. Weigh them before deciding.
- Quote exact text from the input in the evidence field.
- recommended_action must say what to investigate or contain. Never claim an action was already taken."""


def triage_event(event):
    keys = ("rule", "priority", "output", "output_fields")
    text = json.dumps({k: event.get(k) for k in keys}, indent=2)
    return runtime_triager.invoke([("system", FALCO_PROMPT), ("user", text)])