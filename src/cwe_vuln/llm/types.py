"""Shared chat DTOs. Providers return these; the reasoner does not parse SDK objects."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChatResult:
    """One chat completion, stripped of vendor-specific wrappers."""

    text: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_ms: int | None = None
    finish_reason: str | None = None
    provider: str = ""
    model: str = ""
