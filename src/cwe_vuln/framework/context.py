"""Explicit run state for evaluation trials.

Replaces the old module globals ``RAW_LLM_DIR`` and ``REPLAY_RAW_LLM`` so two
jobs cannot overwrite each other's capture directory.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunContext:
    """Where a trial writes raw LLM completions, and whether to replay them.

    ``raw_llm_dir`` is ``None`` in unit tests that call ``trial_pipeline``
    directly: nothing is captured and the provider is always called.
    ``replay`` is set by ``--resume`` so a crashed token-cap run does not
    re-bill the provider for units that already have a raw completion.
    """

    raw_llm_dir: Path | None = None
    replay: bool = False
    should_stop: Callable[[], bool] | None = None
    log: Callable[[str], None] | None = None
