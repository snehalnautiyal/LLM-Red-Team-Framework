"""
cli.py — Command-line interface for the LLM Red-Team Framework.

This is the front door of the tool. When you type:
    python -m llm_redteam.cli --provider openai --model gpt-4o ...

...this file parses your arguments, runs the auth gate, fires the engine,
and writes the report.

Usage examples:
    # Interactive scan (prompts for authorization)
    python -m llm_redteam.cli \\
        --provider openai \\
        --base-url https://api.openai.com/v1 \\
        --model gpt-4o \\
        --api-key $OPENAI_API_KEY

    # CI mode (no interactive prompt)
    python -m llm_redteam.cli \\
        --provider openai --base-url ... --model ... --api-key ... \\
        --ci --authorized

    # Only run injection probes
    python -m llm_redteam.cli ... --categories prompt_injection jailbreak
"""
from __future__ import annotations
import argparse
import logging
import sys
from pathlib import Path

from .adapter import build_adapter
from .auth import confirm_authorization
from .engine import ScanEngine
from .models import TargetConfig, Verdict
from .probes import get_probes
from .reporter import write_reports

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="LLM Red-Team Framework — authorized security testing for LLM apps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--provider", required=True, choices=["openai", "anthropic", "fake"],
                   help="LLM provider")
    p.add_argument("--base-url", required=True, help="API base URL")
    p.add_argument("--model", required=True, help="Model name")
    p.add_argument("--api-key", default="", help="API key (use env var in production)")
    p.add_argument("--categories", nargs="*",
                   choices=["prompt_injection", "jailbreak", "system_prompt_leakage", "data_leakage"],
                   help="Probe categories to run (default: all)")
    p.add_argument("--rate-limit", type=float, default=1.0,
                   help="Seconds to wait between probes (default: 1.0)")
    p.add_argument("--output-dir", default="reports", help="Directory for report files")
    p.add_argument("--ci", action="store_true", help="CI mode: no interactive prompts")
    p.add_argument("--authorized", action="store_true",
                   help="Confirm you are authorized to test this target (required in CI mode)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    config = TargetConfig(
        provider=args.provider,
        base_url=args.base_url,
        model=args.model,
        api_key=args.api_key,
    )

    # Authorization gate — nothing runs until this passes
    confirm_authorization(
        target_id=f"{config.provider}:{config.base_url}",
        ci_mode=args.ci,
        authorized_flag=args.authorized,
    )

    probes = get_probes(args.categories)
    print(f"Running {len(probes)} probe(s)...\n")

    adapter = build_adapter(config)
    engine = ScanEngine(adapter, rate_limit_s=args.rate_limit)
    results = engine.run(probes)

    md_path, json_path = write_reports(results, config.base_url, args.output_dir)
    print(f"\nReports written:")
    print(f"  Markdown : {md_path}")
    print(f"  JSON     : {json_path}")

    # Exit non-zero if any critical finding — lets CI pipelines gate on this
    has_critical = any(
        r.verdict == Verdict.FAIL and r.severity and r.severity.value == "critical"
        for r in results
    )
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
