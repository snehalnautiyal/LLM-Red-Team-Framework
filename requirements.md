# Requirements — LLM Red-Team Framework

## Introduction

This document defines the requirements for a defensive LLM security testing
framework. The tool sends a battery of safety probes to a target LLM endpoint
that the operator owns or is explicitly authorized to test, judges each
response for safe versus unsafe behavior, and produces a scored remediation
report.

The framework's purpose is to help teams find and fix weaknesses in their own
LLM applications before an attacker does. It is a **hardening tool, not an
attack tool**: it must refuse to run against any target the operator has not
confirmed they are authorized to test, and its output is oriented toward fixes,
not toward weaponizing findings against third parties.

Scope of probe categories: prompt injection, jailbreak resistance,
system-prompt leakage, and sensitive-data leakage. Out of scope for this
version: attacking model weights, denial-of-service load testing, and any
network-level exploitation.

---

## Requirement 1: Authorization gate

**User story:** As a security tester, I want the tool to force me to confirm
authorization before any scan, so that I cannot accidentally or carelessly test
a system I do not have permission to test.

**Acceptance criteria:**

- WHEN a scan is started THEN the system SHALL require an explicit
  authorization confirmation before sending any request to the target.
- WHEN the operator does not confirm authorization THEN the system SHALL exit
  without sending any probe.
- WHEN authorization is confirmed THEN the system SHALL record the
  confirmation, the target identifier, and a timestamp in the run log.
- WHERE the tool is run in automated/CI mode THE system SHALL require an
  explicit `--authorized` flag and SHALL refuse to run if it is absent.

---

## Requirement 2: Target configuration and adapter

**User story:** As a tester, I want to point the tool at different kinds of LLM
endpoints, so that I can reuse the same framework across providers and local
models.

**Acceptance criteria:**

- WHEN the operator supplies a target config (provider, base URL, model,
  credentials) THEN the system SHALL validate that all required fields are
  present before starting.
- WHEN a supported provider is selected THEN the system SHALL route requests
  through the matching target adapter.
- WHEN a request to the target fails (timeout, auth error, rate limit) THEN
  the system SHALL retry per a configurable policy and SHALL record the failure
  rather than crashing the run.
- THE system SHALL never log raw credentials in plaintext in any output file.

---

## Requirement 3: Probe library

**User story:** As a tester, I want a library of categorized probes, so that
each run exercises the target across the main classes of LLM weakness.

**Acceptance criteria:**

- THE system SHALL group probes into the categories: `prompt_injection`,
  `jailbreak`, `system_prompt_leakage`, `data_leakage`.
- WHEN a scan runs THEN the system SHALL execute each enabled probe exactly
  once per target unless repeat runs are configured.
- WHERE the operator selects specific categories THE system SHALL run only the
  probes in those categories.
- THE system SHALL define each probe with: a unique `id`, a `category`, an
  `input`, a description of the `expected_safe_behavior`, and a reference to
  its detector.
- THE system SHALL make the probe library extensible so a new probe can be
  added without modifying the core engine.

---

## Requirement 4: Detector and scoring

**User story:** As a tester, I want each response automatically judged as pass
or fail with a severity, so that I get a clear, repeatable result instead of
having to read every reply myself.

**Acceptance criteria:**

- WHEN the target returns a response THEN the system SHALL pass it to the
  probe's detector, which SHALL return a `pass`, `fail`, or `inconclusive`
  result.
- WHEN a probe fails THEN the system SHALL assign a severity of `low`,
  `medium`, `high`, or `critical`.
- WHEN a detector cannot reach a confident verdict THEN the system SHALL mark
  the result as `inconclusive` rather than guessing.
- THE system SHALL produce identical verdicts for identical inputs and responses
  (deterministic scoring).

---

## Requirement 5: Report generation

**User story:** As a tester, I want a clear report at the end of a run, so that
I can share findings and act on fixes.

**Acceptance criteria:**

- WHEN a scan completes THEN the system SHALL produce a report in both
  Markdown and JSON formats.
- THE report SHALL include: target identifier, run timestamp, total probes run,
  counts by result and severity, and a per-probe breakdown.
- WHEN a probe fails THEN the report SHALL include a plain-language explanation
  and a suggested remediation for that finding.
- THE report SHALL present an overall risk summary at the top.

---

## Requirement 6: Run safety and observability

**User story:** As a tester, I want the run to behave predictably and leave a
clear trail, so that I can trust the tool and debug it when something goes wrong.

**Acceptance criteria:**

- THE system SHALL respect a configurable rate limit (seconds between requests).
- WHEN the run is interrupted THEN the system SHALL save partial results.
- THE system SHALL write a run log capturing each probe sent, the verdict, and
  any errors.
- THE system SHALL exit with a non-zero status code if any `critical`-severity
  finding is detected, so it can gate a CI pipeline.

---

## Non-functional requirements

- The framework SHALL be written in Python 3.11+.
- All core logic SHALL be unit-testable offline using a `FakeTargetAdapter`,
  with no live API calls required to run the test suite.
- The README SHALL include a responsible-use section stating the tool is for
  authorized testing only.
