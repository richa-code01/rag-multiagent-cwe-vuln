"""Decoupled LLM provider layer.

The reasoner depends on `ChatProvider`, not on Groq or OpenAI. Swap backends with:

    CWE_VULN_LLM_PROVIDER=openai|groq|together|openrouter|fireworks|deepseek|ollama|custom
    CWE_VULN_LLM_MODEL=...
    CWE_VULN_LLM_API_KEY=...          # always wins
    GROQ_API_KEY / OPENAI_API_KEY / ...  # provider-scoped
    CWE_VULN_LLM_BASE_URL=...         # override or required for `custom`

Add a new OpenAI-compatible host with `register_provider(ProviderSpec(...))`.
"""

from cwe_vuln.llm.errors import LLMError, RateLimitError
from cwe_vuln.llm.provider import ChatProvider, OpenAICompatProvider
from cwe_vuln.llm.spec import (
    DEFAULT_PROVIDER,
    LLM_API_KEY_ENV,
    LLM_BASE_URL_ENV,
    LLM_MODEL_ENV,
    LLM_PROVIDER_ENV,
    ProviderSpec,
    UnknownProviderError,
    api_key_from_env,
    base_url_from_env,
    fallback_models,
    known_providers,
    llm_ready,
    missing_key_message,
    model_from_env,
    provider_name,
    register_provider,
    resolve_spec,
    resolved_spec,
)
from cwe_vuln.llm.types import ChatResult

__all__ = [
    "DEFAULT_PROVIDER",
    "LLM_API_KEY_ENV",
    "LLM_BASE_URL_ENV",
    "LLM_MODEL_ENV",
    "LLM_PROVIDER_ENV",
    "ChatProvider",
    "ChatResult",
    "LLMError",
    "OpenAICompatProvider",
    "ProviderSpec",
    "RateLimitError",
    "UnknownProviderError",
    "api_key_from_env",
    "base_url_from_env",
    "fallback_models",
    "known_providers",
    "llm_ready",
    "missing_key_message",
    "model_from_env",
    "provider_name",
    "register_provider",
    "resolve_spec",
    "resolved_spec",
]
