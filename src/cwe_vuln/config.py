"""Shared knobs only: paths, Top-K, fusion k, LLM env names, seed CWE ids."""

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


class ConfigError(RuntimeError):
    """Raised when shared paths cannot be resolved."""


def repo_root(start: Path | None = None) -> Path:
    """Walk parents until `data/seed/labels.jsonl` is found."""
    cursor = (start or Path(__file__).resolve()).parent
    for path in [cursor, *cursor.parents]:
        if (path / "data" / "seed" / "labels.jsonl").exists():
            return path
    raise ConfigError("Could not locate data/seed/labels.jsonl from the package path.")


@dataclass(frozen=True)
class Settings:
    top_k: int = 5
    rrf_k: int = 60
    llm_env_vars: tuple[str, ...] = ("CWE_VULN_LLM_API_KEY", "OPENAI_API_KEY")

    def llm_api_key(self) -> str | None:
        for name in self.llm_env_vars:
            value = os.environ.get(name)
            if value:
                return value
        return None


settings = Settings()
