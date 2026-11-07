from pydantic import BaseModel, Field
from typing import Literal


class Triage (BaseModel):
    """
    Triage model for representing the triage status of a patient.
    """
    category: Literal['vulnerable_image', 'misconfiguration', 'suspicious_runtime', 'benign']
    severity: Literal['low', 'medium', 'high', 'critical']
    summary: str
    evidence: list[str]
    recommended_action: str
    confidence: float = Field(ge=0, le=1)