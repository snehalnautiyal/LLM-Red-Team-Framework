"""
test_reporter.py — Tests for the report writer.
"""
import json
import tempfile
from pathlib import Path

from llm_redteam.models import ProbeResult, Verdict, Severity
from llm_redteam.reporter import write_reports


def _make_results():
    return [
        ProbeResult(
            probe_id="injection_ignore_system",
            category="prompt_injection",
            verdict=Verdict.FAIL,
            severity=Severity.HIGH,
            reason="Model complied with injected instruction",
            remediation="Add output filtering.",
            response_snippet="HACKED",
        ),
        ProbeResult(
            probe_id="jailbreak_dan_mode",
            category="jailbreak",
            verdict=Verdict.PASS,
            reason="Model maintained guidelines",
        ),
    ]


class TestReporter:
    def test_both_files_created(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            md, js = write_reports(_make_results(), "https://api.example.com", tmpdir)
            assert md.exists()
            assert js.exists()

    def test_markdown_contains_risk_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            md, _ = write_reports(_make_results(), "https://api.example.com", tmpdir)
            content = md.read_text()
            assert "Risk Summary" in content
            assert "injection_ignore_system" in content

    def test_markdown_contains_remediation_for_fail(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            md, _ = write_reports(_make_results(), "https://api.example.com", tmpdir)
            content = md.read_text()
            assert "Add output filtering" in content

    def test_json_is_valid_and_has_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, js = write_reports(_make_results(), "https://api.example.com", tmpdir)
            data = json.loads(js.read_text())
            assert data["summary"]["total"] == 2
            assert data["summary"]["fail"] == 1
            assert data["summary"]["pass"] == 1
            assert len(data["results"]) == 2

    def test_overall_risk_reflects_worst_severity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, js = write_reports(_make_results(), "https://api.example.com", tmpdir)
            data = json.loads(js.read_text())
            assert "HIGH" in data["overall_risk"]

    def test_empty_results_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            md, js = write_reports([], "https://api.example.com", tmpdir)
            assert md.exists()
            data = json.loads(js.read_text())
            assert data["summary"]["total"] == 0
