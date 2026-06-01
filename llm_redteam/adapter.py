"""
adapter.py — TargetAdapter ABC and concrete implementations.

The adapter is the "messenger" that delivers a probe to the model.
By hiding the delivery details behind an interface, the engine works
with OpenAI, Anthropic, or a local model — just swap the adapter.

FakeTargetAdapter is used in tests so no real API calls are needed.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from .models import TargetConfig


class TargetAdapter(ABC):
    @abstractmethod
    def send(self, messages: list[dict]) -> str:
        """
        Send a chat-style message list to the model.
        Returns the model's reply as a plain string.
        messages format: [{"role": "user", "content": "..."}]
        """


class OpenAIAdapter(TargetAdapter):
    """Sends probes to an OpenAI-compatible endpoint via httpx."""

    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    def send(self, messages: list[dict]) -> str:
        import httpx
        resp = httpx.post(
            f"{self.config.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            json={"model": self.config.model, "messages": messages},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


class AnthropicAdapter(TargetAdapter):
    """Sends probes to the Anthropic Messages API via httpx."""

    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    def send(self, messages: list[dict]) -> str:
        import httpx
        resp = httpx.post(
            f"{self.config.base_url}/v1/messages",
            headers={
                "x-api-key": self.config.api_key,
                "anthropic-version": "2023-06-01",
            },
            json={"model": self.config.model, "max_tokens": 512, "messages": messages},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]


class FakeTargetAdapter(TargetAdapter):
    """
    Returns a pre-set response — used in tests so no API key is needed.
    Pass the response you want the 'model' to return when you create it.
    """

    def __init__(self, canned_response: str) -> None:
        self.canned_response = canned_response

    def send(self, messages: list[dict]) -> str:
        return self.canned_response


def build_adapter(config: TargetConfig) -> TargetAdapter:
    """Factory: pick the right adapter based on the provider name."""
    adapters = {
        "openai": OpenAIAdapter,
        "anthropic": AnthropicAdapter,
        "fake": lambda c: FakeTargetAdapter(""),
    }
    if config.provider not in adapters:
        raise ValueError(f"Unknown provider: {config.provider!r}")
    return adapters[config.provider](config)
