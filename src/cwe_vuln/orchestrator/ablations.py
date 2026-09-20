"""Ablation doubles used by the thesis evaluation (C4). Not the system of record."""

from __future__ import annotations

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.retrieval import RankedHit


class EmptyExtractor:
    """No-SAST ablation: the reasoner sees code + retrieval only."""

    def extract(self, unit: SeedUnit) -> list[Evidence]:
        del unit
        return []


class EmptyRetriever:
    """No-retrieval ablation: the reasoner sees code + SAST only."""

    embedder_name = "none"

    def rank_for_unit(self, unit: SeedUnit) -> list[RankedHit]:
        del unit
        return []

    def retrieval_confidence(self, unit: SeedUnit) -> float:
        del unit
        return 0.0

    @staticmethod
    def coverage(evidence, hits) -> None:
        del evidence, hits
        return None
