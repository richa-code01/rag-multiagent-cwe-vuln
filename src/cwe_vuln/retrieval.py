"""Assignment 3: hybrid CWE retrieval (lexical TF-IDF + SAST + relationships).

This is not neural embedding retrieval. TF-IDF cosine is a lexical vector-space
ranker. The second independent signal is the Assignment 1 SAST-style detector
(and optional CWE relationship expansion from Assignment 2). Hybrid combine uses
Reciprocal Rank Fusion (RRF). Metrics are seed-only — not a benchmark.
"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cwe_vuln.dataset import SeedUnit, load_seed, repo_root
from cwe_vuln.detector import match_rules
from cwe_vuln.knowledge import CWEKnowledgeBase, CWEEntry

TOKEN_RE = re.compile(r"[a-z0-9]+")
RRF_K = 60


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


def rrf_combine(*rankings: list[str], k: int = RRF_K) -> list[tuple[str, float]]:
    """Reciprocal Rank Fusion over one or more ordered id lists."""
    scores: dict[str, float] = defaultdict(float)
    for ranking in rankings:
        seen: set[str] = set()
        for rank, doc_id in enumerate(ranking, start=1):
            if doc_id in seen:
                continue
            seen.add(doc_id)
            scores[doc_id] += 1.0 / (k + rank)
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


@dataclass
class HybridRetriever:
    kb: CWEKnowledgeBase
    index: TfidfIndex
    units_by_id: dict[str, SeedUnit]

    @classmethod
    def load(cls, root: Path | None = None) -> HybridRetriever:
        kb = CWEKnowledgeBase.load()
        documents = {entry.id: _entry_document(entry) for entry in kb.entries.values()}
        units = {unit.unit_id: unit for unit in load_seed(root)}
        return cls(kb=kb, index=TfidfIndex(documents), units_by_id=units)

    def lexical_rank(self, query: str) -> list[RankedHit]:
        hits = self.index.rank(query)
        return [_with_name(hit, self.kb) for hit in hits]

    def sast_rank(self, query: RetrievalQuery) -> list[RankedHit]:
        source = ""
        if query.unit_id and query.unit_id in self.units_by_id:
            source = self.units_by_id[query.unit_id].source
        else:
            source = query.query
        matched = [item.cwe_id for item in match_rules(source)]
        # Preserve order, drop duplicates.
        ordered = list(dict.fromkeys(matched))
        return [
            RankedHit(cwe_id=cwe_id, score=1.0, name=_name(self.kb, cwe_id))
            for cwe_id in ordered
        ]

    def relationship_rank(self, seed_ids: list[str]) -> list[RankedHit]:
        """Expand SAST/lexical seeds by one CWE relationship hop."""
        scores: dict[str, float] = {}
        for rank, cwe_id in enumerate(seed_ids[:5], start=1):
            scores[cwe_id] = max(scores.get(cwe_id, 0.0), 1.0 / rank)
            if cwe_id not in self.kb.entries:
                continue
            for related in self.kb.relationships(cwe_id).all_ids():
                scores[related] = max(scores.get(related, 0.0), 0.4 / rank)
        hits = [
            RankedHit(cwe_id=cwe_id, score=score, name=_name(self.kb, cwe_id))
            for cwe_id, score in scores.items()
        ]
        hits.sort(key=lambda item: (-item.score, item.cwe_id))
        return hits

    def hybrid_rank(self, query: RetrievalQuery) -> list[RankedHit]:
        lexical = [hit.cwe_id for hit in self.lexical_rank(query.query)]
        sast = [hit.cwe_id for hit in self.sast_rank(query)]
        related = [hit.cwe_id for hit in self.relationship_rank(sast or lexical[:3])]
        fused = rrf_combine(lexical, sast, related)
        return [
            RankedHit(cwe_id=cwe_id, score=score, name=_name(self.kb, cwe_id))
            for cwe_id, score in fused
        ]


def load_retrieval_queries(root: Path | None = None) -> list[RetrievalQuery]:
    path = (root or repo_root()) / "data" / "retrieval" / "labeled_queries.jsonl"
    queries: list[RetrievalQuery] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        payload = json.loads(raw)
        queries.append(
            RetrievalQuery(
                query_id=str(payload["query_id"]),
                query=str(payload["query"]),
                relevant_cwes=tuple(payload["relevant_cwes"]),
                unit_id=payload.get("unit_id"),
            )
        )
    return queries


def evaluate_retriever(retriever: HybridRetriever, queries: list[RetrievalQuery], k_values: tuple[int, ...] = (1, 3, 5)) -> dict[str, object]:
    systems = {
        "lexical_tfidf": lambda q: [hit.cwe_id for hit in retriever.lexical_rank(q.query)],
        "sast": lambda q: [hit.cwe_id for hit in retriever.sast_rank(q)],
        "hybrid_rrf": lambda q: [hit.cwe_id for hit in retriever.hybrid_rank(q)],
    }
    report: dict[str, object] = {
        "assignment": 3,
        "evaluation_scope": "authored_seed_only",
        "seed_only_not_a_benchmark": True,
        "disclaimer": (
            "seed-only — not a benchmark. Queries are the 12 unit notes plus 6 short "
            "descriptions. TF-IDF is lexical (not neural embeddings). Hybrid is RRF of "
            "TF-IDF + SAST-style rules + CWE relationship expansion."
        ),
        "n_queries": len(queries),
        "k_values": list(k_values),
        "systems": {},
        "per_query": [],
    }
    per_query: list[dict[str, object]] = []
    system_scores: dict[str, dict[str, list[float]]] = {
        name: {f"recall@{k}": [] for k in k_values} | {"mrr": []} for name in systems
    }

    for query in queries:
        row: dict[str, object] = {
            "query_id": query.query_id,
            "unit_id": query.unit_id,
            "relevant_cwes": list(query.relevant_cwes),
            "rankings": {},
        }
        for name, rank_fn in systems.items():
            ranked = rank_fn(query)
            row["rankings"][name] = ranked[:5]
            for k in k_values:
                system_scores[name][f"recall@{k}"].append(recall_at_k(query.relevant_cwes, ranked, k))
            system_scores[name]["mrr"].append(mean_reciprocal_rank(query.relevant_cwes, ranked))
        per_query.append(row)

    systems_out = {}
    for name, buckets in system_scores.items():
        systems_out[name] = {metric: round(mean(values), 4) for metric, values in buckets.items()}
    report["systems"] = systems_out
    report["per_query"] = per_query
    return report


def _entry_document(entry: CWEEntry) -> str:
    mit = " ".join(f"{item.title} {item.text}" for item in entry.mitigations)
    return f"{entry.id} {entry.name} {entry.description} {mit} {entry.detection_notes}"


def _name(kb: CWEKnowledgeBase, cwe_id: str) -> str:
    entry = kb.entries.get(cwe_id)
    return entry.name if entry else ""


def _with_name(hit: RankedHit, kb: CWEKnowledgeBase) -> RankedHit:
    return RankedHit(cwe_id=hit.cwe_id, score=hit.score, name=_name(kb, hit.cwe_id))


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
