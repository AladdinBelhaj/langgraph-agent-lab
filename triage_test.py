import os

from langchain_openai import ChatOpenAI
from schema import Triage

finding = """Package: openssl 1.1.1k-1
Vulnerability: CVE-2022-0778
Severity: HIGH
Status: fixed
Fixed version: 1.1.1n-0+deb10u1
Title: openssl: infinite loop in BN_mod_sqrt() reachable when parsing certificates
Target: nginx:1.19 (debian 10.9)"""

triager = ChatOpenAI(
    model=os.environ["LLM_MODEL"],
    base_url=os.environ["LLM_BASE_URL"],
    api_key=os.environ["LLM_API_KEY"],
    temperature=0,
).with_structured_output(Triage)

system_prompt = """You triage one vulnerability finding from a Trivy scan. Set category to "vulnerability".

Priority:
- fix_now: severity CRITICAL or HIGH and a fixed version exists.
- fix_soon: severity MEDIUM with a fixed version, or CRITICAL/HIGH with no fix yet (recommend a mitigation and tracking upstream).
- monitor: severity LOW, or MEDIUM with no fix available.

Rules:
- Use only the evidence given. Do not invent details.
- Quote exact text from the input in the evidence field.
- recommended_action must be concrete. Name the exact fixed version when the input gives one."""


def triage(text):
    return triager.invoke([
        ("system", system_prompt),
        ("user", text),
    ])


print(triage(finding))