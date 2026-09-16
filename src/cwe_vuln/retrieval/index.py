"""In-memory TF-IDF cosine index. Lexical only; no neural embeddings."""

from __future__ import annotations

import math
import re
from collections import defaultdict

from cwe_vuln.models.retrieval import RankedHit

TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


class TfidfIndex:
    """In-memory TF-IDF cosine index (lexical, not neural)."""

    def __init__(self, documents: dict[str, str]) -> None:
        self.doc_ids = list(documents)
        self.doc_tokens = {doc_id: tokenize(text) for doc_id, text in documents.items()}
        df: dict[str, int] = defaultdict(int)
        for tokens in self.doc_tokens.values():
            for token in set(tokens):
                df[token] += 1
        n_docs = max(len(self.doc_ids), 1)
        self.idf = {token: math.log((n_docs + 1) / (count + 1)) + 1.0 for token, count in df.items()}
        self.vectors = {doc_id: self._tfidf(tokens) for doc_id, tokens in self.doc_tokens.items()}

    def _tfidf(self, tokens: list[str]) -> dict[str, float]:
        tf: dict[str, int] = defaultdict(int)
        for token in tokens:
            tf[token] += 1
        vec = {token: (count / len(tokens)) * self.idf.get(token, 0.0) for token, count in tf.items()} if tokens else {}
        return _l2_normalize(vec)

    def rank(self, query: str) -> list[RankedHit]:
        qvec = self._tfidf(tokenize(query))
        hits = [
            RankedHit(cwe_id=doc_id, score=_cosine(qvec, self.vectors[doc_id]))
            for doc_id in self.doc_ids
        ]
        hits.sort(key=lambda item: (-item.score, item.cwe_id))
        return hits


def _l2_normalize(vec: dict[str, float]) -> dict[str, float]:
    norm = math.sqrt(sum(value * value for value in vec.values()))
    if norm == 0:
        return vec
    return {key: value / norm for key, value in vec.items()}


def _cosine(left: dict[str, float], right: dict[str, float]) -> float:
    if not left or not right:
        return 0.0
    keys = left.keys() & right.keys()
    return sum(left[key] * right[key] for key in keys)
