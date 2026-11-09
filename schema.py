from typing import Literal

from pydantic import BaseModel, Field


class Triage(BaseModel):
    """Triage of one Trivy finding: what it is, how urgent, and the concrete fix."""

    category: Literal["vulnerability", "misconfiguration", "secret"]
    priority: Literal["fix_now", "fix_soon", "monitor"]
    summary: str
    evidence: list[str]
    recommended_action: str
    confidence: float = Field(ge=0, le=1)

class RuntimeTriage(BaseModel):
    """Triage of one Falco runtime alert from a container."""

    category: Literal["suspicious", "benign"]
    severity: Literal["low", "medium", "high", "critical"]
    summary: str
    evidence: list[str]
    recommended_action: str