"""Shared pipeline/validation result types. Orchestrator wires them; it does not redefine them."""

from __future__ import annotations

from dataclasses import dataclass

from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.reasoning import ReasoningResult
from cwe_vuln.models.retrieval import RankedHit


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class ValidationReport:
    unit_id: str
    passed: bool
    checks: tuple[CheckResult, ...]
    warnings: tuple[CheckResult, ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "unit_id": self.unit_id,
            "passed": self.passed,
            "checks": [check.__dict__ for check in self.checks],
        }
        if self.warnings:
            payload["warnings"] = [item.__dict__ for item in self.warnings]
        return payload


@dataclass(frozen=True)
class PipelineResult:
    unit_id: str
    path: str
    evidence: tuple[Evidence, ...]
    hits: tuple[RankedHit, ...]
    result: ReasoningResult
    report: ValidationReport
    reasoner: str = "template"
    embedder: str = "tfidf_fallback"

    def to_dict(self) -> dict[str, object]:
        return {
            "unit_id": self.unit_id,
            "path": self.path,
            "reasoner": self.reasoner,
            "embedder": self.embedder,
            "evidence": [item.to_dict() for item in self.evidence],
            "hits": [{"cwe_id": hit.cwe_id, "score": hit.score, "name": hit.name} for hit in self.hits],
            "reasoning": self.result.to_dict(),
            "validation": self.report.to_dict(),
        }
