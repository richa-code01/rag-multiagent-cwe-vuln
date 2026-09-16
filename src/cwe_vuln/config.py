"""Shared settings (paths stay in dataset.repo_root; policy knobs live here)."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    top_k: int = 5
    rrf_k: int = 60
    # Hybrid RRF uses three lists; there are no extra numeric weights beyond rank fusion.
    llm_env_vars: tuple[str, ...] = ("CWE_VULN_LLM_API_KEY", "OPENAI_API_KEY")

    def llm_api_key(self) -> str | None:
        for name in self.llm_env_vars:
            value = os.environ.get(name)
            if value:
                return value
        return None


settings = Settings()
