"""Retrieval query and ranked-hit DTOs. Scoring logic lives in `retrieval/`."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RetrievalQuery:
    query_id: str
    query: str
    relevant_cwes: tuple[str, ...]
    unit_id: str | None = None


@dataclass(frozen=True)
class RankedHit:
    cwe_id: str
    score: float
    name: str = ""
    passage: str = ""  # retrieved CWE prose shown to the LLM (RAG grounding)
