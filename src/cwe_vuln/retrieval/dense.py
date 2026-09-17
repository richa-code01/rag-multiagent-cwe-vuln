"""Cosine ranker over embedder vectors. Independent of MiniLM; tests inject a fake embedder."""

from __future__ import annotations

import math
from typing import Sequence

from cwe_vuln.models.retrieval import RankedHit
from cwe_vuln.retrieval.embed import Embedder, Matrix


def l2_normalize(vec: Sequence[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in vec))
    if norm == 0:
        return [float(value) for value in vec]
    return [float(value) / norm for value in vec]


def dot(left: Sequence[float], right: Sequence[float]) -> float:
    n = min(len(left), len(right))
    return sum(left[i] * right[i] for i in range(n))


def cosine_rank(
    query_vec: Sequence[float],
    doc_ids: Sequence[str],
    doc_matrix: Matrix,
) -> list[RankedHit]:
    query = l2_normalize(query_vec)
    hits = [
        RankedHit(cwe_id=doc_id, score=dot(query, l2_normalize(row)))
        for doc_id, row in zip(doc_ids, doc_matrix)
    ]
    hits.sort(key=lambda item: (-item.score, item.cwe_id))
    return hits


class DenseIndex:
    def __init__(self, documents: dict[str, str], embedder: Embedder) -> None:
        self.doc_ids = list(documents)
        self.embedder = embedder
        texts = [documents[doc_id] for doc_id in self.doc_ids]
        encoded = embedder.encode(texts) if self.doc_ids else []
        self.matrix = [l2_normalize(row) for row in encoded]

    def rank(self, query: str) -> list[RankedHit]:
        rows = self.embedder.encode([query])
        query_vec = rows[0] if rows else []
        query_vec = l2_normalize(query_vec)
        hits = [
            RankedHit(cwe_id=doc_id, score=dot(query_vec, row))
            for doc_id, row in zip(self.doc_ids, self.matrix)
        ]
        hits.sort(key=lambda item: (-item.score, item.cwe_id))
        return hits
