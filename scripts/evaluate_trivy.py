import os

from langchain_openai import ChatOpenAI
from triage_agent.schema import Triage

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


curl_medium_fixed = """Package: libcurl4 7.64.0-4
Vulnerability: CVE-2022-32221
Severity: MEDIUM
Status: fixed
Fixed version: 7.64.0-4+deb10u4
Title: curl: POST following PUT confusion
Target: nginx:1.19 (debian 10.9)"""

glibc_high_nofix = """Package: libc6 2.28-10
Vulnerability: CVE-2019-1010022
Severity: HIGH
Status: affected
Fixed version: none available
Title: glibc: stack guard protection bypass
Target: nginx:1.19 (debian 10.9)"""

tar_medium_nofix = """Package: tar 1.30+dfsg-6
Vulnerability: CVE-2005-2541
Severity: MEDIUM
Status: will_not_fix
Fixed version: none available
Title: tar: does not properly warn the user when extracting setuid or setgid files
Target: nginx:1.19 (debian 10.9)"""

bash_low_fixed = """Package: bash 5.0-4
Vulnerability: CVE-2019-18276
Severity: LOW
Status: fixed
Fixed version: 5.0-4+deb10u1
Title: bash: when effective UID is not equal to its real UID the saved UID is not dropped
Target: nginx:1.19 (debian 10.9)"""

cases = [
    ("openssl_high_fixed", finding, "fix_now"),
    ("curl_medium_fixed", curl_medium_fixed, "fix_soon"),
    ("glibc_high_nofix", glibc_high_nofix, "fix_soon"),
    ("tar_medium_nofix", tar_medium_nofix, "monitor"),
    ("bash_low_fixed", bash_low_fixed, "monitor"),
]

for name, text, expected in cases:
    correct = 0
    for _ in range(3):
        if triage(text).priority == expected:
            correct += 1
    print(f"{name}: {correct}/3")