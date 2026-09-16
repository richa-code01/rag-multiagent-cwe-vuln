"""Agent-facing protocols. Implementations live in sibling modules."""

from __future__ import annotations

from typing import Protocol

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.evidence import Evidence
from cwe_vuln.retrieval import RankedHit
from cwe_vuln.schema import ReasoningResult


class EvidenceExtractor(Protocol):
    def extract(self, unit: SeedUnit) -> list[Evidence]: ...


class UnitRetriever(Protocol):
    def rank_for_unit(self, unit: SeedUnit) -> list[RankedHit]: ...


class UnitReasoner(Protocol):
    def compose(
        self,
        unit: SeedUnit,
        evidence: list[Evidence],
        hits: list[RankedHit],
    ) -> ReasoningResult: ...
