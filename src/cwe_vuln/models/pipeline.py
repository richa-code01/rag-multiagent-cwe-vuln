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
    # LLM diagnostics (None/0 for the deterministic template path).
    model: str | None = None
    provider: str | None = None
    fallback_reason: str | None = None
    n_attempts: int = 0
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_ms: int | None = None
    prompt_chars: int | None = None
    truncated: bool | None = None
    slice_strategy: str | None = None
    cwe_clamped_from: str | None = None
    # Stage signals + fused confidence (ApproachDoc stage 6).
    risk_score: float = 0.0
    retrieval_confidence: float = 0.0
    coverage: float | None = None
    final_confidence: float = 0.0

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "unit_id": self.unit_id,
            "path": self.path,
            "reasoner": self.reasoner,
            "embedder": self.embedder,
            "evidence": [item.to_dict() for item in self.evidence],
            "hits": [{"cwe_id": hit.cwe_id, "score": hit.score, "name": hit.name} for hit in self.hits],
            "reasoning": self.result.to_dict(),
            "validation": self.report.to_dict(),
        }
        diagnostics = {
            "model": self.model,
            "provider": self.provider,
            "fallback_reason": self.fallback_reason,
            "n_attempts": self.n_attempts,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "latency_ms": self.latency_ms,
            "prompt_chars": self.prompt_chars,
            "truncated": self.truncated,
            "slice_strategy": self.slice_strategy,
            "cwe_clamped_from": self.cwe_clamped_from,
        }
        payload["diagnostics"] = {key: value for key, value in diagnostics.items() if value is not None}
        signals: dict[str, object] = {
            "risk_score": self.risk_score,
            "retrieval_confidence": self.retrieval_confidence,
            "final_confidence": self.final_confidence,
        }
        if self.coverage is not None:
            signals["coverage"] = self.coverage
        payload["signals"] = signals
        return payload
