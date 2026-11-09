import os

from langchain_openai import ChatOpenAI
from .schema import Triage

triager = ChatOpenAI(
    model=os.environ["LLM_MODEL"],
    base_url=os.environ["LLM_BASE_URL"],
    api_key=os.environ["LLM_API_KEY"],
    temperature=0,
    max_retries=5,
).with_structured_output(Triage)

TRIVY_PROMPT = """You triage one finding from a Trivy scan. The finding is a vulnerability, a misconfiguration or a hardcoded secret. Set category to match.

Priority for a vulnerability:
- fix_now: severity CRITICAL or HIGH and a fixed version exists.
- fix_soon: severity MEDIUM with a fixed version, or CRITICAL/HIGH with no fix yet (recommend a mitigation and tracking upstream).
- monitor: severity LOW, or MEDIUM with no fix available.

Priority for a misconfiguration:
- fix_now: severity CRITICAL or HIGH.
- fix_soon: severity MEDIUM.
- monitor: severity LOW.

Priority for a secret: always fix_now. Recommend rotating the credential and removing it from the repository history, because deleting the line does not remove it from past commits. The match is masked, so never guess the secret's value.

Rules:
- Use only the evidence given. Do not invent details.
- Quote exact text from the input in the evidence field.
- recommended_action must be concrete. Name the exact fixed version or setting when the input gives one."""


def triage(text):
    return triager.invoke([
        ("system", TRIVY_PROMPT),
        ("user", text),
    ])