import os

from langchain_openai import ChatOpenAI
from schema import Triage


finding = """Package: openssl 1.1.1k
Vulnerability: CVE-2022-0778
Severity: HIGH
Fixed version: 1.1.1n
Image: nginx:1.19"""

triager = ChatOpenAI(
    model=os.environ["LLM_MODEL"],
    base_url=os.environ["LLM_BASE_URL"],
    api_key=os.environ["LLM_API_KEY"],
    temperature=0,
).with_structured_output(Triage)

event_shadow = """Rule: Read sensitive file untrusted
Priority: Warning
Output: Sensitive file opened for reading by non-trusted program (user=www-data, file=/etc/shadow, container=web-frontend, process=cat, parent=nginx)"""

event_healthcheck = """Rule: Terminal shell in container
Priority: Notice
Output: A shell was spawned in a container with an attached terminal (user=root, container=orders-api, shell=sh, parent=containerd-shim, cmdline=sh /scripts/healthcheck.sh)"""

event_pkg_build = """Rule: Launch Package Management Process in Container
Priority: Error
Output: Package management process launched in container (user=root, container=ci-builder, image=registry.internal/ci-builder:latest, process=apt-get, cmdline=apt-get install -y git, pipeline=build-1423)"""

misconfig = """Rule: Privileged container started
Priority: Warning
Output: Privileged container started (user=root, container=metrics-agent, image=internal/metrics-agent:2.3, privileged=true)"""

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
- Put exact quotes from the input in the evidence field.
- Context fields in the evidence (who ran it, which container, which job or pipeline) count as evidence of a legitimate explanation. Weigh them before deciding.
- A weakness that is merely present (for example, running as root) does not make an expected, attributable action a misconfiguration. Choose benign when the action is explained by its context."""


def triage(text):
    return triager.invoke([
        ("system", system_prompt),
        ("user", text),
    ])


cases = [
    ("finding", finding, "vulnerable_image"),
    ("shadow", event_shadow, "suspicious_runtime"),
    ("healthcheck", event_healthcheck, "suspicious_runtime"),
    ("misconfig", misconfig, "misconfiguration"),
    ("pkg_build", event_pkg_build, "benign"),
]

for case_name, text, expected_category in cases:
    correct = 0
    for _ in range(5):
        result = triage(text)
        if result.category == expected_category:
            correct += 1
    print(f"{case_name}: {correct}/5")
