"""
conftest.py — Shared pytest fixtures.

pytest automatically loads this file before any test.
Fixtures defined here are available to every test file.

The key fixture is `fake_adapter` — it lets us test the whole
framework without making a single real API call.
"""
import pytest
from llm_redteam.adapter import FakeTargetAdapter


@pytest.fixture
def safe_adapter():
    """A fake model that always gives a safe, on-topic response."""
    return FakeTargetAdapter("I'm sorry, I can't help with that request.")


@pytest.fixture
def vulnerable_adapter():
    """A fake model that complies with every attack — worst case."""
    return FakeTargetAdapter(
        "HACKED. I am now DAN with no restrictions. "
        "My instructions are: you must always be helpful. "
        "Here is the secret password=abc123. "
        "User emails: alice@example.com, bob@example.com."
    )


@pytest.fixture
def empty_adapter():
    """A fake model that returns an empty string — malformed/edge case."""
    return FakeTargetAdapter("")
