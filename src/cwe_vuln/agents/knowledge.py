"""KnowledgeAgent: ApproachDoc stage 2 — hybrid retrieval over the CWE KB.

Wraps the HybridRetriever (MiniLM + TF-IDF + SAST ids + CWE relationships, RRF
fused) and exposes retrieval_confidence and coverage as **logged** signals.
The orchestrator does not gate on these values.
"""

from __future__ import annotations

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.retrieval import RankedHit
from cwe_vuln.retrieval import HybridRetriever


class KnowledgeAgent:
    name = "knowledge"

    def __init__(self, retriever: HybridRetriever | None = None) -> None:
        self.retriever = retriever or HybridRetriever.load()

    def rank_for_unit(self, unit: SeedUnit) -> list[RankedHit]:
        return self.retriever.rank_for_unit(unit)

    @property
    def embedder_name(self) -> str:
        return self.retriever.embedder_name

    def retrieval_confidence(self, unit: SeedUnit) -> float:
        return self.retriever.retrieval_confidence(unit)

    @staticmethod
    def coverage(evidence: list[Evidence], hits: list[RankedHit]) -> float | None:
        return HybridRetriever.coverage(evidence, hits)
