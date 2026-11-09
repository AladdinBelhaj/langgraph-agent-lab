from fastapi import FastAPI
from pydantic import BaseModel
from .schema import Triage
from .triage_core import triage
from .trivy_input import parse_report

app = FastAPI(title="Container security triage agent")


class FindingIn(BaseModel):
    text: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/triage/trivy")
def triage_trivy(report: dict, limit: int = 5):
    findings = parse_report(report)[:limit]
    return [
        {
            "id": f["id"],
            "kind": f["kind"],
            "severity": f["severity"],
            "triage": triage(f["text"]),
           }
        for f in findings
    ]