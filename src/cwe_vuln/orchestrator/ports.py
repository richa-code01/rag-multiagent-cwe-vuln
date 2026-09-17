"""Agent-facing protocols. Implementations live in sast / retrieval / reasoner / validator."""

from __future__ import annotations

from typing import Protocol

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.pipeline import ValidationReport
from cwe_vuln.models.reasoning import ReasoningResult
from cwe_vuln.models.retrieval import RankedHit


class UnitValidator(Protocol):
    def check(
        self,
        result: ReasoningResult,
        unit: SeedUnit,
        evidence: list[Evidence],
    ) -> ValidationReport: ...


class EvidenceExtractor(Protocol):
    def extract(self, unit: SeedUnit) -> list[Evidence]: ...


class UnitRetriever(Protocol):
    def rank_for_unit(self, unit: SeedUnit) -> list[RankedHit]: ...


class UnitReasoner(Protocol):
    def reason(
        self,
        unit: SeedUnit,
        evidence: list[Evidence],
        hits: list[RankedHit],
    ) -> ReasoningResult: ...
