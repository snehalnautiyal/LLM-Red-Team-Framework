# LLM Red-Team Framework — Steering File

This is a **defensive** LLM security testing framework. It tests prompt
injection, jailbreak resistance, and system-prompt leakage against
LLM endpoints the user owns or is authorized to test. It must include
an explicit authorization/consent gate before any scan, and it outputs
a remediation report — never raw exploits for unauthorized use.

Tech stack: Python 3.11, pytest, httpx, pydantic, rich for reports.

## Core principles
- Authorization gate is mandatory and cannot be bypassed.
- Output is always remediation-oriented (how to fix), never weaponized.
- All core logic must be testable offline with a FakeTargetAdapter.
- No credentials are ever logged in plaintext.
