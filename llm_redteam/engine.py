"""
engine.py — ScanEngine: the main loop that runs every probe.

This is the heart of the framework. It:
1. Takes a list of probes and a target adapter.
2. Sends each probe's input to the model via the adapter.
3. Passes the reply to the probe's detector.
4. Collects a ProbeResult for every probe.
5. Sleeps between probes to respect rate limits.
"""
from __future__ import annotations
import logging
import time

from .adapter import TargetAdapter
from .models import ProbeResult, Verdict
from .probe import Probe

logger = logging.getLogger(__name__)


class ScanEngine:
    def __init__(self, adapter: TargetAdapter, rate_limit_s: float = 1.0) -> None:
        self.adapter = adapter
        self.rate_limit_s = rate_limit_s

    def run(self, probes: list[Probe]) -> list[ProbeResult]:
        results: list[ProbeResult] = []
        for i, probe in enumerate(probes):
            if i > 0:
                time.sleep(self.rate_limit_s)
            result = self._run_one(probe)
            results.append(result)
            logger.info("[%s] %s → %s", probe.category, probe.id, result.verdict)
        return results

    def _run_one(self, probe: Probe) -> ProbeResult:
        messages = [{"role": "user", "content": probe.input}]
        try:
            response = self.adapter.send(messages)
        except Exception as exc:
            logger.error("Probe %s failed to get response: %s", probe.id, exc)
            return ProbeResult(
                probe_id=probe.id,
                category=probe.category,
                verdict=Verdict.INCONCLUSIVE,
                reason=f"Request error: {exc}",
                remediation=probe.remediation,
                response_snippet="",
            )

        try:
            verdict, reason = probe.get_detector().judge(response)
        except Exception as exc:
            logger.error("Detector for %s raised: %s", probe.id, exc)
            return ProbeResult(
                probe_id=probe.id,
                category=probe.category,
                verdict=Verdict.INCONCLUSIVE,
                reason=f"Detector error: {exc}",
                remediation=probe.remediation,
                response_snippet=response[:200],
            )

        return ProbeResult(
            probe_id=probe.id,
            category=probe.category,
            verdict=verdict,
            severity=probe.severity if verdict == Verdict.FAIL else None,
            reason=reason,
            remediation=probe.remediation if verdict == Verdict.FAIL else "",
            response_snippet=response[:200],
        )
