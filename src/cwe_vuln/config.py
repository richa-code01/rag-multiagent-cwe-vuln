"""Shared knobs only: paths, Top-K, fusion k, Groq env names, seed CWE ids."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


SEED_CWE_IDS: tuple[str, ...] = (
    "CWE-89",
    "CWE-79",
    "CWE-22",
    "CWE-502",
    "CWE-798",
    "CWE-327",
)

# CWE_VULN_LLM_API_KEY overrides GROQ_API_KEY. OPENAI_API_KEY is ignored.
LLM_KEY_ENV_VARS: tuple[str, ...] = ("CWE_VULN_LLM_API_KEY", "GROQ_API_KEY")
LLM_MODEL_ENV = "CWE_VULN_LLM_MODEL"
LLM_BASE_URL_ENV = "CWE_VULN_LLM_BASE_URL"
DEFAULT_LLM_MODEL = "openai/gpt-oss-20b"
DEFAULT_LLM_BASE_URL = "https://api.groq.com/openai/v1"
MINILM_MODEL_ID = "all-MiniLM-L6-v2"


class ConfigError(RuntimeError):
    """Raised when shared paths cannot be resolved."""


class MissingLLMKeyError(ConfigError):
    """Raised when the default live pipeline is used without a Groq key."""


MISSING_LLM_KEY_MESSAGE = (
    "GROQ_API_KEY is required for the default live research pipeline. "
    "Set GROQ_API_KEY in the gitignored .env file or export it. "
    "Use --offline (cwe-vuln-pipeline) or --ablation template (cwe-vuln-eval) "
    "only for paper comparison tables. SAST-only and TemplateReasoner scored "
    "F1=0 on the 24-unit research split and are not the system of record."
)


def require_llm_api_key() -> str:
    """Return the Groq (or override) key, or raise MissingLLMKeyError."""
    key = settings.llm_api_key()
    if not key:
        raise MissingLLMKeyError(MISSING_LLM_KEY_MESSAGE)
    return key


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

    def llm_api_key(self) -> str | None:
        """CWE_VULN_LLM_API_KEY overrides GROQ_API_KEY. OPENAI_API_KEY is ignored."""
        for name in self.llm_env_vars:
            value = os.environ.get(name, "").strip()
            if value:
                return value
        return None

    def llm_model(self) -> str:
        return os.environ.get(LLM_MODEL_ENV, "").strip() or self.default_llm_model

    def llm_base_url(self) -> str:
        return os.environ.get(LLM_BASE_URL_ENV, "").strip() or self.default_llm_base_url


settings = Settings()
