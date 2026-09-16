"""Rank fusion and retrieval-eval helpers. Binary P/R/F1 lives in models.metrics."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from cwe_vuln.config import settings


def rrf_combine(*rankings: list[str], k: int | None = None) -> list[tuple[str, float]]:
    """Reciprocal Rank Fusion over one or more ordered id lists."""
    fuse_k = settings.rrf_k if k is None else k
    scores: dict[str, float] = defaultdict(float)
    for ranking in rankings:
        seen: set[str] = set()
        for rank, doc_id in enumerate(ranking, start=1):
            if doc_id in seen:
                continue
            seen.add(doc_id)
            scores[doc_id] += 1.0 / (fuse_k + rank)
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def recall_at_k(relevant: Iterable[str], ranked: list[str], k: int) -> float:
    gold = set(relevant)
    if not gold:
        return 0.0
    return len(gold.intersection(ranked[:k])) / len(gold)


def mean_reciprocal_rank(relevant: Iterable[str], ranked: list[str]) -> float:
    gold = set(relevant)
    for index, doc_id in enumerate(ranked, start=1):
        if doc_id in gold:
            return 1.0 / index
    return 0.0


def mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)
