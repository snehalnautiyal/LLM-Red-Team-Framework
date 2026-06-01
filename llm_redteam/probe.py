"""
probe.py — Probe abstract base class.

A Probe is one "attack note" — a crafted message we send to the model.
Each probe knows:
  - What to send (input)
  - What safe behaviour looks like (expected_safe_behavior)
  - How to judge the reply (detector)
  - How bad it is if the model fails (severity)
  - How to fix it (remediation)
"""
from abc import ABC, abstractmethod
from .detector import Detector
from .models import Severity


class Probe(ABC):
    id: str                      # Unique slug, e.g. "injection_ignore_system"
    category: str                # "prompt_injection" | "jailbreak" | etc.
    input: str                   # The message sent to the model
    expected_safe_behavior: str  # Human description of what a safe model does
    severity: Severity           # How bad a failure is
    remediation: str             # Fix advice included in the report

    @abstractmethod
    def get_detector(self) -> Detector:
        """Return the Detector paired with this probe."""
