"""Shared knobs only: paths, Top-K, fusion k, LLM provider env, seed CWE ids."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cwe_vuln.llm.spec import (
    LLM_API_KEY_ENV,
    api_key_from_env,
    base_url_from_env,
    llm_ready,
    missing_key_message,
    model_from_env,
    resolve_spec,
)

SEED_CWE_IDS: tuple[str, ...] = (
    "CWE-89",
    "CWE-79",
    "CWE-22",
    "CWE-502",
    "CWE-798",
    "CWE-327",
)

# Re-exported so existing imports keep working. Provider-specific keys live in llm.spec.
LLM_KEY_ENV_VARS: tuple[str, ...] = (LLM_API_KEY_ENV, "GROQ_API_KEY")
DEFAULT_LLM_PROVIDER = "groq"
DEFAULT_LLM_MODEL = resolve_spec("groq").default_model
DEFAULT_LLM_BASE_URL = resolve_spec("groq").base_url
MINILM_MODEL_ID = "all-MiniLM-L6-v2"


class ConfigError(RuntimeError):
    """Raised when shared paths cannot be resolved."""


class MissingLLMKeyError(ConfigError):
    """Raised when the default live pipeline is used without a provider key."""


def require_llm_api_key() -> str:
    """Return the selected provider's key, or a dummy key for local providers."""
    spec = resolve_spec()
    key = api_key_from_env(spec)
    if key:
        return key
    if not spec.requires_key:
        return spec.name
    raise MissingLLMKeyError(missing_key_message(spec))


def repo_root(start: Path | None = None) -> Path:
    """Walk parents until `data/seed/labels.jsonl` is found."""
    cursor = (start or Path(__file__).resolve()).parent
    for path in [cursor, *cursor.parents]:
        if (path / "data" / "seed" / "labels.jsonl").exists():
            return path
    raise ConfigError("Could not locate data/seed/labels.jsonl from the package path.")


def cache_dir() -> Path:
    return repo_root() / ".cache"


def minilm_cache_dir() -> Path:
    return cache_dir() / "sentence-transformers"


def load_project_env() -> None:
    """Load repo-root `.env` if present. Missing file or package is a no-op."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    try:
        env_file = repo_root() / ".env"
    except ConfigError:
        return
    if env_file.is_file():
        load_dotenv(env_file, override=False)


load_project_env()


@dataclass(frozen=True)
class Settings:
    top_k: int = 5
    rrf_k: int = 60
    prompt_max_chars: int = 4000
    retrieval_query_chars: int = 1500
    llm_env_vars: tuple[str, ...] = LLM_KEY_ENV_VARS
    use_llm_if_available: bool = True
    skip_llm_when_sast_hits: bool = False
    use_neural_if_available: bool = True
    minilm_model: str = MINILM_MODEL_ID
    default_llm_model: str = DEFAULT_LLM_MODEL
    default_llm_base_url: str = DEFAULT_LLM_BASE_URL

    def llm_provider(self) -> str:
        from cwe_vuln.llm.spec import provider_name

        return provider_name()

    def llm_api_key(self) -> str | None:
        """Universal CWE_VULN_LLM_API_KEY, else the selected provider's key env."""
        return api_key_from_env()

    def llm_ready(self) -> bool:
        return llm_ready()

    def llm_model(self) -> str:
        return model_from_env() or self.default_llm_model

    def llm_base_url(self) -> str:
        return base_url_from_env() or self.default_llm_base_url


settings = Settings()

# Default-provider snapshot for older imports; require_llm_api_key() uses the live provider.
MISSING_LLM_KEY_MESSAGE = missing_key_message()
