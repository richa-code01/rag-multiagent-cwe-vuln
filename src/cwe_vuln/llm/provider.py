"""ChatProvider port and the OpenAI-compatible implementation used by every preset.

A new vendor that speaks `/chat/completions` needs a `ProviderSpec` row, not a
new class. A vendor that does not can implement `ChatProvider` and pass it to
`LLMReasoner(provider=...)`.
"""

from __future__ import annotations

import time
from typing import Any, Protocol, runtime_checkable

from cwe_vuln.llm.errors import RateLimitError
from cwe_vuln.llm.spec import (
    ProviderSpec,
    api_key_from_env,
    base_url_from_env,
    json_mode_from_env,
    model_from_env,
    resolve_spec,
)
from cwe_vuln.llm.types import ChatResult


@runtime_checkable
class ChatProvider(Protocol):
    """Minimal chat port. The reasoner depends on this, not on openai/Groq SDKs."""

    name: str
    model: str
    base_url: str
    api_key: str

    def complete(self, messages: list[dict[str, str]], *, json_mode: bool | None = None) -> ChatResult:
        ...


class OpenAICompatProvider:
    """One client for Groq, OpenAI, Together, OpenRouter, Ollama, and custom hosts."""

    def __init__(
        self,
        *,
        name: str,
        api_key: str,
        model: str,
        base_url: str,
        json_mode: bool = True,
    ) -> None:
        if not model:
            raise ValueError("OpenAICompatProvider requires a model id (set CWE_VULN_LLM_MODEL)")
        if not base_url:
            raise ValueError("OpenAICompatProvider requires a base URL (set CWE_VULN_LLM_BASE_URL)")
        self.name = name
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.json_mode = json_mode

    @classmethod
    def from_spec(
        cls,
        spec: ProviderSpec,
        *,
        api_key: str,
        model: str | None = None,
        base_url: str | None = None,
    ) -> OpenAICompatProvider:
        return cls(
            name=spec.name,
            api_key=api_key,
            model=model or model_from_env(spec),
            base_url=base_url or base_url_from_env(spec),
            json_mode=json_mode_from_env(spec),
        )

    @classmethod
    def from_env(
        cls,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        provider: str | None = None,
    ) -> OpenAICompatProvider | None:
        """Build from env, or None when a required key is missing."""
        spec = resolve_spec(provider)
        key = api_key if api_key is not None else api_key_from_env(spec)
        if not key:
            if spec.requires_key:
                return None
            key = spec.name  # ollama accepts any dummy key
        url = base_url if base_url is not None else base_url_from_env(spec)
        model_id = model if model is not None else model_from_env(spec)
        if spec.name == "custom" and (not url or not model_id):
            raise ValueError(
                "Provider 'custom' needs CWE_VULN_LLM_BASE_URL and CWE_VULN_LLM_MODEL"
            )
        return cls.from_spec(spec, api_key=key, model=model_id, base_url=url)

    def complete(self, messages: list[dict[str, str]], *, json_mode: bool | None = None) -> ChatResult:
        from openai import OpenAI

        kwargs: dict[str, Any] = {
            "api_key": self.api_key,
            "base_url": self.base_url,
            "timeout": 90.0,
            "max_retries": 0,
        }
        client = OpenAI(**kwargs)
        create_kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
        }
        use_json = self.json_mode if json_mode is None else json_mode
        if use_json:
            create_kwargs["response_format"] = {"type": "json_object"}
        started = time.monotonic()
        try:
            response = client.chat.completions.create(**create_kwargs)
        except Exception as exc:
            if _looks_like_rate_limit(exc):
                raise RateLimitError(str(exc)) from exc
            raise
        latency_ms = int((time.monotonic() - started) * 1000)
        usage = getattr(response, "usage", None)
        choice = response.choices[0]
        return ChatResult(
            text=choice.message.content or "",
            prompt_tokens=_usage_int(usage, "prompt_tokens"),
            completion_tokens=_usage_int(usage, "completion_tokens"),
            latency_ms=latency_ms,
            finish_reason=getattr(choice, "finish_reason", None),
            provider=self.name,
            model=self.model,
        )


def _usage_int(usage: object, field: str) -> int | None:
    if usage is None:
        return None
    value = getattr(usage, field, None)
    return int(value) if value is not None else None


def _looks_like_rate_limit(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None) or getattr(exc, "http_status", None)
    if status == 429:
        return True
    name = type(exc).__name__.lower()
    if "ratelimit" in name or "rate_limit" in name:
        return True
    text = str(exc).lower()
    return "429" in text or "rate limit" in text or "tokens per day" in text or "quota" in text
