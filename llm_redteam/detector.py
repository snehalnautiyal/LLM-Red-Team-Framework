"""
detector.py — Detector abstract base class.

A Detector reads the model's reply and decides: did the model behave safely?
All detectors use keyword/regex matching — no LLM calls — so they are:
  - Deterministic (same input → same output, always)
  - Fast (no network)
  - Testable offline
"""
from abc import ABC, abstractmethod
from .models import Verdict


class Detector(ABC):
    @abstractmethod
    def judge(self, response: str) -> tuple[Verdict, str]:
        """
        Analyse the model's response text.
        Returns (Verdict, reason_string).
        Must be deterministic.
        """
