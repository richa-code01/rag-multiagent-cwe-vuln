"""Hybrid retriever: neural (or TF-IDF fallback) + SAST ids + CWE relationships, RRF fused.

Does not instantiate the reasoner. Units are loaded only to supply source for the SAST signal.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from cwe_vuln.config import repo_root, settings
from cwe_vuln.dataset import DatasetError, SeedUnit, load_research_corpus, load_seed
from cwe_vuln.knowledge import CWEKnowledgeBase
from cwe_vuln.models.retrieval import RankedHit, RetrievalQuery
from cwe_vuln.retrieval.dense import DenseIndex
from cwe_vuln.retrieval.embed import Embedder, MiniLMEmbedder, default_allow_download
from cwe_vuln.retrieval.index import TfidfIndex
from cwe_vuln.retrieval.rank import mean, mean_reciprocal_rank, recall_at_k, rrf_combine
from cwe_vuln.sast import match_rules


@dataclass
class HybridRetriever:
    kb: CWEKnowledgeBase
    index: TfidfIndex
    units_by_id: dict[str, SeedUnit]
    dense: DenseIndex | None = None
    embedder_name: str = "tfidf_fallback"
    documents: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(
        cls,
        root: Path | None = None,
        embedder: Embedder | None = None,
        allow_download: bool | None = None,
    ) -> HybridRetriever:
        kb = CWEKnowledgeBase.load()
        documents = passage_documents(kb)
        units = {unit.unit_id: unit for unit in load_seed(root)}
        try:
            for unit in load_research_corpus(root):
                units.setdefault(unit.unit_id, unit)
        except DatasetError:
            pass
        index = TfidfIndex(documents)
        dense: DenseIndex | None = None
        name = "tfidf_fallback"
        if embedder is not None:
            dense = DenseIndex(documents, embedder)
            name = getattr(embedder, "name", "custom")
        elif settings.use_neural_if_available:
            allow = default_allow_download() if allow_download is None else allow_download
            neural = MiniLMEmbedder.try_load(allow_download=allow)
            if neural is not None:
                dense = DenseIndex(documents, neural)
                name = "minilm"
        return cls(
            kb=kb,
            index=index,
            units_by_id=units,
            dense=dense,
            embedder_name=name,
            documents=documents,
        )

    def lexical_rank(self, query: str) -> list[RankedHit]:
        return self._collapse(self.index.rank(query))

    def neural_rank(self, query: str) -> list[RankedHit]:
        if self.dense is None:
            return self.lexical_rank(query)
        return self._collapse(self.dense.rank(query))

    def _collapse(self, hits: list[RankedHit]) -> list[RankedHit]:
        """Collapse passage-level hits (``CWE-89::main``) to one hit per CWE id,
        keeping the best-scoring passage as the grounding text."""
        best: dict[str, RankedHit] = {}
        for hit in hits:
            cwe_id, passage = split_passage_id(hit.cwe_id, self.documents)
            collapsed = RankedHit(
                cwe_id=cwe_id,
                score=hit.score,
                name=_name(self.kb, cwe_id),
                passage=passage,
            )
            current = best.get(cwe_id)
            if current is None or hit.score > current.score:
                best[cwe_id] = collapsed
        ordered = sorted(best.values(), key=lambda item: (-item.score, item.cwe_id))
        return ordered

    def sast_rank(self, query: RetrievalQuery) -> list[RankedHit]:
        source = ""
        if query.unit_id and query.unit_id in self.units_by_id:
            source = self.units_by_id[query.unit_id].source
        else:
            source = query.query
        matched = [item.cwe_id for item in match_rules(source)]
        ordered = list(dict.fromkeys(matched))
        return [
            RankedHit(cwe_id=cwe_id, score=1.0, name=_name(self.kb, cwe_id), passage=self.passage_for(cwe_id))
            for cwe_id in ordered
        ]

    def relationship_rank(self, seed_ids: list[str]) -> list[RankedHit]:
        """Expand SAST/neural seeds by one CWE relationship hop."""
        scores: dict[str, float] = {}
        for rank, cwe_id in enumerate(seed_ids[:5], start=1):
            scores[cwe_id] = max(scores.get(cwe_id, 0.0), 1.0 / rank)
            if cwe_id not in self.kb.entries:
                continue
            for related in self.kb.relationships(cwe_id).all_ids():
                scores[related] = max(scores.get(related, 0.0), 0.4 / rank)
        hits = [
            RankedHit(cwe_id=cwe_id, score=score, name=_name(self.kb, cwe_id), passage=self.passage_for(cwe_id))
            for cwe_id, score in scores.items()
        ]
        hits.sort(key=lambda item: (-item.score, item.cwe_id))
        return hits

    def hybrid_rank(self, query: RetrievalQuery) -> list[RankedHit]:
        neural = [hit.cwe_id for hit in self.neural_rank(query.query)]
        lexical = [hit.cwe_id for hit in self.lexical_rank(query.query)]
        sast = [hit.cwe_id for hit in self.sast_rank(query)]
        related = [hit.cwe_id for hit in self.relationship_rank(sast or neural[:3] or lexical[:3])]
        fused = rrf_combine(neural, sast, related)
        return [
            RankedHit(cwe_id=cwe_id, score=score, name=_name(self.kb, cwe_id), passage=self.passage_for(cwe_id))
            for cwe_id, score in fused
        ]

    def passage_for(self, cwe_id: str, max_chars: int = 700) -> str:
        """Grounding prose for one CWE: main passage preferred, truncated."""
        key = f"{cwe_id}::main"
        text = self.documents.get(key) or self.documents.get(cwe_id) or ""
        if len(text) > max_chars:
            return text[:max_chars].rstrip() + " ..."
        return text

    def rank_for_unit(self, unit: SeedUnit) -> list[RankedHit]:
        """Unit-level retrieve: evidence/sink window as the query, source as the
        SAST signal, truncated to config.top_k. ``unit.notes`` is never used here:
        benchmark adapters put gold labels (``real=true``, CWE ids) in notes."""
        from cwe_vuln.dataset.sanitize import retrieval_query_text

        self.units_by_id[unit.unit_id] = unit
        query = RetrievalQuery(
            query_id=unit.unit_id,
            query=retrieval_query_text(unit),
            relevant_cwes=(),
            unit_id=unit.unit_id,
        )
        return self.hybrid_rank(query)[: settings.top_k]

    def retrieval_confidence(self, unit: SeedUnit) -> float:
        """Cosine similarity of the best passage to the source excerpt.

        MiniLM cosine when the neural index is loaded, TF-IDF cosine otherwise.
        Clamped to [0, 1]; 0.0 when the index returns nothing. Not a calibrated
        probability.
        """
        from cwe_vuln.dataset.sanitize import retrieval_query_text

        query = retrieval_query_text(unit)
        rank = self.neural_rank if self.dense is not None else self.lexical_rank
        hits = rank(query)
        if not hits:
            return 0.0
        return round(min(1.0, max(0.0, hits[0].score)), 4)

    @staticmethod
    def coverage(evidence, hits) -> float | None:
        """Fraction of evidence CWE ids present in the retrieved hits.

        None when there is no evidence (coverage is undefined, not zero).
        """
        evidence_cwes = {item.cwe_id for item in evidence}
        if not evidence_cwes:
            return None
        hit_cwes = {hit.cwe_id for hit in hits}
        return round(len(evidence_cwes & hit_cwes) / len(evidence_cwes), 4)


def load_retrieval_queries(
    root: Path | None = None,
    files: tuple[str, ...] = ("labeled_queries.jsonl",),
) -> list[RetrievalQuery]:
    base = (root or repo_root()) / "data" / "retrieval"
    queries: list[RetrievalQuery] = []
    for name in files:
        path = Path(name)
        path = path if path.is_absolute() else base / name
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


def evaluate_retriever(
    retriever: HybridRetriever,
    queries: list[RetrievalQuery],
    k_values: tuple[int, ...] = (1, 3, 5),
) -> dict[str, object]:
    systems = {
        "lexical_tfidf": lambda q: [hit.cwe_id for hit in retriever.lexical_rank(q.query)],
        "neural": lambda q: [hit.cwe_id for hit in retriever.neural_rank(q.query)],
        "sast": lambda q: [hit.cwe_id for hit in retriever.sast_rank(q)],
        "hybrid_rrf": lambda q: [hit.cwe_id for hit in retriever.hybrid_rank(q)],
    }
    neural_note = (
        "MiniLM cosine (all-MiniLM-L6-v2)"
        if retriever.embedder_name == "minilm"
        else "TF-IDF fallback (MiniLM unavailable or skipped)"
    )
    report: dict[str, object] = {
        "assignment": 3,
        "evaluation_scope": "authored_seed_only",
        "seed_only_not_a_benchmark": True,
        "embedder": retriever.embedder_name,
        "disclaimer": (
            "seed-only — not a benchmark. Queries are the 12 unit notes plus 6 short "
            "descriptions. lexical_tfidf is TF-IDF cosine. neural is "
            f"{neural_note}. Hybrid is RRF of neural + SAST-style rules + CWE "
            "relationship expansion."
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
            row["rankings"][name] = ranked[: max(k_values)]
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


def passage_documents(kb: CWEKnowledgeBase) -> dict[str, str]:
    """One CWE entry → several passages so MiniLM/TF-IDF index focused text.

    Keys are ``CWE-89::main`` / ``::mitigations`` / ``::detection``; ranking
    collapses them back to one hit per CWE id.
    """
    documents: dict[str, str] = {}
    for entry in kb.entries.values():
        main = f"{entry.id} {entry.name}. {entry.description}"
        if entry.extended_description:
            main += f" {entry.extended_description}"
        if entry.consequences:
            main += f" Consequences: {entry.consequences}"
        documents[f"{entry.id}::main"] = main
        if entry.mitigations:
            mit = " ".join(f"{item.title}: {item.text}" for item in entry.mitigations)
            documents[f"{entry.id}::mitigations"] = f"{entry.id} {entry.name} mitigations. {mit}"
        if entry.detection_notes:
            documents[f"{entry.id}::detection"] = f"{entry.id} {entry.name} detection. {entry.detection_notes}"
    return documents


def split_passage_id(doc_id: str, documents: dict[str, str]) -> tuple[str, str]:
    """Map a passage doc id back to (cwe_id, passage text)."""
    cwe_id = doc_id.split("::", 1)[0]
    return cwe_id, documents.get(doc_id, "")


def _name(kb: CWEKnowledgeBase, cwe_id: str) -> str:
    entry = kb.entries.get(cwe_id)
    return entry.name if entry else ""
