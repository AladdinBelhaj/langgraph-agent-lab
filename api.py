from fastapi import FastAPI
from pydantic import BaseModel

from schema import Triage
from triage_core import triage

app = FastAPI(title="Container security triage agent")


class FindingIn(BaseModel):
    text: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/triage", response_model=Triage)
def triage_finding(body: FindingIn):
    return triage(body.text)