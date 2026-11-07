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

result = triager.invoke(finding)

print(result)