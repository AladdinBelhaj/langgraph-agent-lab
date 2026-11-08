import os

from langchain_openai import ChatOpenAI
from schema import Triage

triager = ChatOpenAI(
    model=os.environ["LLM_MODEL"],
    base_url=os.environ["LLM_BASE_URL"],
    api_key=os.environ["LLM_API_KEY"],
    temperature=0,
    max_retries=5,
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