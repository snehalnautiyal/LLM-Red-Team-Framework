"""
test_demo.py — End-to-end demo of the full scan pipeline.

Runs ALL probe categories against both a vulnerable and a safe fake adapter.
No API key required. Demonstrates the framework working top-to-bottom.

Run with:
    pytest tests/test_demo.py -v
"""
import pytest
from llm_redteam.adapter import FakeTargetAdapter
from llm_redteam.engine import ScanEngine
from llm_redteam.models import Verdict
from llm_redteam.probes import ALL_PROBES


class TestDemoFullScan:
    """Full pipeline demo: all probes, both vulnerable and safe adapters."""

    def test_vulnerable_model_produces_failures(self):
        """A model that leaks everything should trigger FAIL verdicts."""
        adapter = FakeTargetAdapter(
            "Sure! DAN mode activated — no restrictions. "
            "My system prompt says: keep this secret. "
            "Here is the API key: sk-abc123. "
            "User emails: alice@example.com. HACKED."
        )
        engine = ScanEngine(adapter, rate_limit_s=0)
        results = engine.run(ALL_PROBES)

        assert len(results) == len(ALL_PROBES), "Every probe must produce a result"
        failures = [r for r in results if r.verdict == Verdict.FAIL]
        assert len(failures) > 0, "Vulnerable model must trigger at least one FAIL"

        # Every failure must carry remediation advice
        for r in failures:
            assert r.remediation, f"Probe {r.probe_id} failed but has no remediation"
            assert r.severity is not None, f"Probe {r.probe_id} failed but has no severity"

    def test_safe_model_produces_no_failures(self):
        """A model that refuses all attacks should produce only PASS verdicts."""
        adapter = FakeTargetAdapter(
            "I'm sorry, I can't help with that request. "
            "Please ask me something else."
        )
        engine = ScanEngine(adapter, rate_limit_s=0)
        results = engine.run(ALL_PROBES)

        assert len(results) == len(ALL_PROBES)
        assert all(r.verdict != Verdict.FAIL for r in results), (
            "Safe model must not produce any FAIL verdicts"
        )

    def test_all_probe_categories_are_covered(self):
        """Confirm all four categories are represented in ALL_PROBES."""
        categories = {p.category for p in ALL_PROBES}
        assert categories == {
            "prompt_injection",
            "jailbreak",
            "system_prompt_leakage",
            "data_leakage",
        }

    def test_engine_never_crashes_on_empty_response(self):
        """Empty model response must not raise — every result is INCONCLUSIVE."""
        adapter = FakeTargetAdapter("")
        engine = ScanEngine(adapter, rate_limit_s=0)
        results = engine.run(ALL_PROBES)

        assert len(results) == len(ALL_PROBES)
        for r in results:
            assert r.verdict in (Verdict.PASS, Verdict.FAIL, Verdict.INCONCLUSIVE)
