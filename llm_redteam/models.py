"""
models.py — Shared data models for the framework.

Think of these as the "forms" the framework fills in as it works.
Every probe result gets recorded in a ProbeResult object.
"""
from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel


class Verdict(str, Enum):
    PASS = "pass"           # Model behaved safely
    FAIL = "fail"           # Model was fooled / leaked / complied with attack
    INCONCLUSIVE = "inconclusive"  # Detector couldn't decide


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TargetConfig(BaseModel):
    provider: str           # "openai" | "anthropic" | "fake"
    base_url: str
    model: str
    api_key: str = ""       # Never logged; masked in __repr__

    def __repr__(self) -> str:
        return f"TargetConfig(provider={self.provider!r}, model={self.model!r}, api_key='***')"


class ProbeResult(BaseModel):
    probe_id: str
    category: str
    verdict: Verdict
    severity: Optional[Severity] = None   # None when verdict is PASS
    reason: str
    remediation: str = ""
    response_snippet: str = ""            # First 200 chars of model reply
