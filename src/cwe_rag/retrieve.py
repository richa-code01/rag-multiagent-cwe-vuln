"""Lexical retriever over the seed CWE knowledge base.

No embeddings, API keys, or vector database — token overlap is enough for
the seed slice and keeps tests deterministic.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from cwe_rag.knowledge import SEED_CWES, CweRecord

_TOKEN = re.compile(r"[a-z0-9]+", re.IGNORECASE)


def tokenize(text: str) -> list[str]:
    return [tok.lower() for tok in _TOKEN.findall(text)]


@dataclass(frozen=True)
class RetrievalHit:
    record: CweRecord
    score: float


def _document_tokens(record: CweRecord) -> list[str]:
    parts = [record.cwe_id, record.name, record.summary, *record.keywords]
    return tokenize(" ".join(parts))


def retrieve(query: str, *, k: int = 3) -> list[RetrievalHit]:
    """Rank seed CWE records by TF-style overlap with the query."""
    q_tokens = tokenize(query)
    if not q_tokens:
        return []
    q_set = set(q_tokens)
    hits: list[RetrievalHit] = []
    for record in SEED_CWES:
        doc = _document_tokens(record)
        if not doc:
            continue
        overlap = sum(1 for tok in doc if tok in q_set)
        # Mild length normalization so short records are not over-ranked.
        score = overlap / math.sqrt(len(doc))
        if score > 0:
            hits.append(RetrievalHit(record=record, score=score))
    hits.sort(key=lambda h: (-h.score, h.record.cwe_id))
    return hits[:k]
