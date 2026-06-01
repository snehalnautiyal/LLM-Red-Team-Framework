# Design — LLM Red-Team Framework

## Module layout

```
llm_redteam/
├── __init__.py
├── models.py          # Pydantic data models (ProbeResult, Severity, Verdict, TargetConfig)
├── auth.py            # Authorization gate
├── adapter.py         # TargetAdapter ABC + OpenAI/Anthropic/Fake implementations
├── probe.py           # Probe ABC
├── detector.py        # Detector ABC
├── engine.py          # Scan engine — runs probes through adapters
├── reporter.py        # Markdown + JSON report writer
└── probes/
    ├── __init__.py
    ├── injection.py   # Prompt-injection probes
    ├── jailbreak.py   # Jailbreak probes
    ├── leakage.py     # System-prompt leakage probes
    └── data.py        # Data-leakage probes

tests/
├── conftest.py        # Shared fixtures (FakeTargetAdapter)
├── test_injection.py
├── test_jailbreak.py
├── test_leakage.py
└── test_reporter.py

reports/               # Generated output (gitignored except .gitkeep)
```

---

## Component diagram

```
┌─────────────────────────────────────────────────────────┐
│                        CLI (cli.py)                      │
│  parse args → call AuthGate → call Engine.run()          │
└───────────────────────┬─────────────────────────────────┘
                        │
              ┌─────────▼──────────┐
              │     AuthGate       │  ← Req 1
              │  confirm + log     │
              └─────────┬──────────┘
                        │
              ┌─────────▼──────────┐
              │    ScanEngine      │  ← Req 3, 4, 6
              │  for each Probe:   │
              │    adapter.send()  │
              │    detector.judge()│
              │    collect result  │
              └──┬──────────────┬──┘
                 │              │
    ┌────────────▼───┐   ┌──────▼──────────┐
    │ TargetAdapter  │   │    Probe + Det.  │
    │  (ABC)         │   │    (ABC pair)    │
    │  OpenAI impl   │   │  injection/      │
    │  Anthropic impl│   │  jailbreak/      │
    │  Fake impl     │   │  leakage/data    │
    └────────────────┘   └─────────────────┘
                        │
              ┌─────────▼──────────┐
              │     Reporter       │  ← Req 5
              │  Markdown + JSON   │
              └────────────────────┘
```

---

## Key abstractions

### TargetAdapter (adapter.py)

```python
class TargetAdapter(ABC):
    @abstractmethod
    def send(self, messages: list[dict]) -> str:
        """Send a chat-style message list, return the model's reply text."""
```

Concrete implementations: `OpenAIAdapter`, `AnthropicAdapter`, `FakeTargetAdapter`.
The engine only ever calls `adapter.send()` — swapping providers requires zero
engine changes.

### Probe (probe.py)

```python
class Probe(ABC):
    id: str           # unique slug, e.g. "injection_ignore_system"
    category: str     # "prompt_injection" | "jailbreak" | "system_prompt_leakage" | "data_leakage"
    input: str        # the crafted message sent to the model
    expected_safe_behavior: str  # human description of what a safe model does

    @abstractmethod
    def detector(self) -> "Detector":
        """Return the Detector instance paired with this probe."""
```

### Detector (detector.py)

```python
class Detector(ABC):
    @abstractmethod
    def judge(self, response: str) -> tuple[Verdict, str]:
        """
        Returns (Verdict.PASS | FAIL | INCONCLUSIVE, reason_string).
        Must be deterministic: same input → same output, always.
        """
```

Detectors use keyword/pattern matching (no LLM calls) so they are fast,
offline, and deterministic.

### ProbeResult (models.py)

```python
class ProbeResult(BaseModel):
    probe_id: str
    category: str
    verdict: Verdict          # PASS | FAIL | INCONCLUSIVE
    severity: Severity | None # LOW | MEDIUM | HIGH | CRITICAL (None on PASS)
    reason: str
    remediation: str          # populated from probe metadata on FAIL
    response_snippet: str     # first 200 chars of model reply
```

### ScanEngine (engine.py)

```python
class ScanEngine:
    def run(self, probes, adapter, rate_limit_s) -> list[ProbeResult]:
        results = []
        for probe in probes:
            response = adapter.send(...)
            verdict, reason = probe.detector().judge(response)
            results.append(ProbeResult(...))
            time.sleep(rate_limit_s)
        return results
```

### Reporter (reporter.py)

Takes `list[ProbeResult]` + target config, writes:
- `reports/<timestamp>_report.md` — human-readable with risk summary at top
- `reports/<timestamp>_report.json` — machine-readable for CI/tooling

### AuthGate (auth.py)

```python
def confirm_authorization(target_id: str, ci_mode: bool, authorized_flag: bool) -> None:
    """
    Interactive: prompts user to type 'yes I am authorized'.
    CI mode: requires authorized_flag=True or raises SystemExit.
    Logs confirmation + timestamp to run log on success.
    """
```

---

## Data flow (one probe, end to end)

```
CLI args
  → AuthGate.confirm()          # blocks until confirmed
  → TargetConfig validated
  → ScanEngine.run(probes, adapter)
      → probe.input sent via adapter.send()
      → model reply returned
      → probe.detector().judge(reply) → (FAIL, "leaked system prompt marker")
      → ProbeResult(severity=HIGH, remediation="Add output filtering...")
  → Reporter.write(results)
      → reports/2026-06-01_report.md
      → reports/2026-06-01_report.json
  → exit(1) if any CRITICAL result
```

---

## Design decisions

| Decision | Choice | Reason |
|---|---|---|
| Detector strategy | Keyword/regex, no LLM | Deterministic, offline, fast |
| Probe extensibility | Register via list in `probes/__init__.py` | No engine changes needed |
| Auth in CI | `--authorized` flag required | Prevents accidental runs |
| Credentials | Never logged; masked in config repr | Security hygiene |
| Rate limiting | `time.sleep` between probes | Simple, configurable, avoids overwhelming target |
