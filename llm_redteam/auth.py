"""
auth.py — Authorization gate.

This is the most important safety feature of the framework.
Before a single probe is sent, the operator MUST confirm they own
or are authorized to test the target.

Think of it like the disclaimer you sign before a penetration test.
Without it, this tool would be indistinguishable from an attack tool.

Two modes:
  - Interactive: prompts the user to type a confirmation phrase.
  - CI mode: requires --authorized flag; no interactive prompt.
"""
from __future__ import annotations
import logging
import sys
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_REQUIRED_PHRASE = "yes i am authorized"


def confirm_authorization(
    target_id: str,
    ci_mode: bool = False,
    authorized_flag: bool = False,
) -> None:
    """
    Block until authorization is confirmed, or exit if it is not.

    Args:
        target_id:       A string identifying the target (e.g. base URL).
        ci_mode:         True when running in a CI pipeline (no stdin).
        authorized_flag: True if --authorized was passed on the CLI.

    Raises:
        SystemExit: If authorization is not confirmed.
    """
    if ci_mode:
        if not authorized_flag:
            print(
                "\n[AUTH GATE] CI mode requires --authorized flag.\n"
                "You must explicitly confirm you are authorized to test this target.\n"
                "Aborting.",
                file=sys.stderr,
            )
            sys.exit(1)
        _log_confirmation(target_id)
        return

    print("\n" + "=" * 60)
    print("  LLM RED-TEAM FRAMEWORK — AUTHORIZATION GATE")
    print("=" * 60)
    print(f"\n  Target: {target_id}")
    print("\n  This tool will send security probes to the target above.")
    print("  You MUST own this system or have written authorization to test it.")
    print("  Unauthorized testing is illegal in most jurisdictions.\n")
    print(f'  Type exactly: "{_REQUIRED_PHRASE}"')
    print("  (or press Ctrl+C to abort)\n")

    try:
        answer = input("  Your confirmation: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.")
        sys.exit(0)

    if answer != _REQUIRED_PHRASE:
        print("\n[AUTH GATE] Confirmation not accepted. Aborting.", file=sys.stderr)
        sys.exit(1)

    _log_confirmation(target_id)
    print("\n[AUTH GATE] Authorization confirmed. Starting scan...\n")


def _log_confirmation(target_id: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    logger.info("Authorization confirmed | target=%s | timestamp=%s", target_id, ts)
