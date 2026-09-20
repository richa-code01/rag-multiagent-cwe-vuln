"""Named LLM provider presets. Adding a host is one row here, not a reasoner change.

Every preset is OpenAI-compatible chat-completions (Groq, OpenAI, Together,
OpenRouter, Fireworks, DeepSeek, Ollama, or a custom base URL). The reasoner
talks to `ChatProvider`; it never hardcodes a vendor URL.

Switch at runtime with env (no code change):

    CWE_VULN_LLM_PROVIDER=openai
    OPENAI_API_KEY=sk-...
    CWE_VULN_LLM_MODEL=gpt-4o-mini

Or a one-off host:

    CWE_VULN_LLM_PROVIDER=custom
    CWE_VULN_LLM_BASE_URL=https://api.example.com/v1
    CWE_VULN_LLM_MODEL=my-model
    CWE_VULN_LLM_API_KEY=...
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace

LLM_PROVIDER_ENV = "CWE_VULN_LLM_PROVIDER"
LLM_MODEL_ENV = "CWE_VULN_LLM_MODEL"
LLM_BASE_URL_ENV = "CWE_VULN_LLM_BASE_URL"
LLM_API_KEY_ENV = "CWE_VULN_LLM_API_KEY"
LLM_JSON_MODE_ENV = "CWE_VULN_LLM_JSON_MODE"
DEFAULT_PROVIDER = "groq"


@dataclass(frozen=True)
class ProviderSpec:
    """One named backend. `key_env` is tried after the universal override key."""

    name: str
    base_url: str
    default_model: str
    key_env: tuple[str, ...]
    fallback_models: tuple[str, ...] = ()
    json_mode: bool = True
    requires_key: bool = True
    notes: str = ""


# Universal override is always checked first (see api_key_from_env).
_PROVIDERS: dict[str, ProviderSpec] = {
    "groq": ProviderSpec(
        name="groq",
        base_url="https://api.groq.com/openai/v1",
        default_model="openai/gpt-oss-20b",
        key_env=("GROQ_API_KEY",),
        fallback_models=("openai/gpt-oss-20b", "openai/gpt-oss-120b", "qwen/qwen3.8-27b"),
        notes="Default thesis path. Free-tier key; 200k tokens/day observed cap.",
    ),
    "openai": ProviderSpec(
        name="openai",
        base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini",
        key_env=("OPENAI_API_KEY",),
        fallback_models=("gpt-4o-mini", "gpt-4o"),
    ),
    "together": ProviderSpec(
        name="together",
        base_url="https://api.together.xyz/v1",
        default_model="meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
        key_env=("TOGETHER_API_KEY",),
    ),
    "openrouter": ProviderSpec(
        name="openrouter",
        base_url="https://openrouter.ai/api/v1",
        default_model="openai/gpt-oss-20b",
        key_env=("OPENROUTER_API_KEY",),
    ),
    "fireworks": ProviderSpec(
        name="fireworks",
        base_url="https://api.fireworks.ai/inference/v1",
        default_model="accounts/fireworks/models/llama-v3p1-8b-instruct",
        key_env=("FIREWORKS_API_KEY",),
    ),
    "deepseek": ProviderSpec(
        name="deepseek",
        base_url="https://api.deepseek.com/v1",
        default_model="deepseek-chat",
        key_env=("DEEPSEEK_API_KEY",),
    ),
    "ollama": ProviderSpec(
        name="ollama",
        base_url="http://127.0.0.1:11434/v1",
        default_model="llama3.1",
        key_env=("OLLAMA_API_KEY",),
        requires_key=False,
        notes="Local OpenAI-compatible server. Empty key is sent as 'ollama'.",
    ),
    "custom": ProviderSpec(
        name="custom",
        base_url="",
        default_model="",
        key_env=(),
        notes="Requires CWE_VULN_LLM_BASE_URL and CWE_VULN_LLM_MODEL.",
    ),
}


class UnknownProviderError(ValueError):
    """Raised when CWE_VULN_LLM_PROVIDER is not a registered name."""


def known_providers() -> tuple[str, ...]:
    return tuple(sorted(_PROVIDERS))


def register_provider(spec: ProviderSpec) -> None:
    """Add or replace a named preset at runtime (tests, extra hosts)."""
    _PROVIDERS[spec.name] = spec


def provider_name() -> str:
    return (os.environ.get(LLM_PROVIDER_ENV, "") or DEFAULT_PROVIDER).strip().lower()


def resolve_spec(name: str | None = None) -> ProviderSpec:
    key = (name or provider_name()).strip().lower()
    spec = _PROVIDERS.get(key)
    if spec is None:
        raise UnknownProviderError(
            f"Unknown LLM provider {key!r}. Known: {', '.join(known_providers())}. "
            "Use CWE_VULN_LLM_PROVIDER=custom with CWE_VULN_LLM_BASE_URL for any "
            "OpenAI-compatible host."
        )
    return spec


def api_key_from_env(spec: ProviderSpec | None = None) -> str | None:
    """CWE_VULN_LLM_API_KEY always wins, then the selected provider's key env vars."""
    spec = spec if spec is not None else resolve_spec()
    override = os.environ.get(LLM_API_KEY_ENV, "").strip()
    if override:
        return override
    for env_name in spec.key_env:
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    return None


def model_from_env(spec: ProviderSpec | None = None) -> str:
    spec = spec if spec is not None else resolve_spec()
    return os.environ.get(LLM_MODEL_ENV, "").strip() or spec.default_model


def base_url_from_env(spec: ProviderSpec | None = None) -> str:
    spec = spec if spec is not None else resolve_spec()
    return os.environ.get(LLM_BASE_URL_ENV, "").strip() or spec.base_url


def json_mode_from_env(spec: ProviderSpec | None = None) -> bool:
    spec = spec if spec is not None else resolve_spec()
    raw = os.environ.get(LLM_JSON_MODE_ENV, "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    return spec.json_mode


def fallback_models(spec: ProviderSpec | None = None) -> tuple[str, ...]:
    spec = spec if spec is not None else resolve_spec()
    return spec.fallback_models


def llm_ready(spec: ProviderSpec | None = None) -> bool:
    """True when from_env() can build a provider (key present, or local host)."""
    spec = spec if spec is not None else resolve_spec()
    if api_key_from_env(spec):
        return True
    return not spec.requires_key


def missing_key_message(spec: ProviderSpec | None = None) -> str:
    spec = spec if spec is not None else resolve_spec()
    keys = (LLM_API_KEY_ENV,) + spec.key_env
    key_list = ", ".join(keys) if keys else LLM_API_KEY_ENV
    return (
        f"No API key found for LLM provider '{spec.name}'. "
        f"Set one of: {key_list}. Copy .env.example to the gitignored .env. "
        f"Known providers: {', '.join(known_providers())}. "
        "Use --offline (cwe-vuln-pipeline) or --ablation template (cwe-vuln-eval) "
        "only for paper comparison tables."
    )


def resolved_spec() -> ProviderSpec:
    """Spec with env overrides applied (base_url / default_model)."""
    spec = resolve_spec()
    return replace(
        spec,
        base_url=base_url_from_env(spec),
        default_model=model_from_env(spec),
        json_mode=json_mode_from_env(spec),
    )
