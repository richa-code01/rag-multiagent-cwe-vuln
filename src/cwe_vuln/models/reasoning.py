"""Assignment 4 reasoning payload types. Schema I/O lives in `schema/`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

SCHEMA_VERSION = "1.0"
Decision = Literal["vulnerable", "not_vulnerable", "uncertain"]


@dataclass(frozen=True)
class CWERef:
    id: str
    name: str

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> CWERef:
        return cls(id=str(payload["id"]), name=str(payload["name"]))


@dataclass(frozen=True)
class SourceSpan:
    path: str
    start_line: int
    end_line: int
    snippet: str

    def to_dict(self) -> dict[str, str | int]:
        return {
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "snippet": self.snippet,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> SourceSpan:
        return cls(
            path=str(payload["path"]),
            start_line=int(payload["start_line"]),
            end_line=int(payload["end_line"]),
            snippet=str(payload["snippet"]),
        )


@dataclass(frozen=True)
class ReasoningResult:
    """Internal model that dumps/loads the Assignment 4 JSON Schema."""

    unit_id: str
    decision: Decision
    cwe: CWERef
    supporting_source_lines: SourceSpan
    root_cause: str
    explanation: str
    remediation: str
    schema_version: str = SCHEMA_VERSION
    confidence: float | None = None
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "unit_id": self.unit_id,
            "decision": self.decision,
            "cwe": self.cwe.to_dict(),
            "supporting_source_lines": self.supporting_source_lines.to_dict(),
            "root_cause": self.root_cause,
            "explanation": self.explanation,
            "remediation": self.remediation,
        }
        if self.confidence is not None:
            payload["confidence"] = self.confidence
        if self.evidence_ids:
            payload["evidence_ids"] = list(self.evidence_ids)
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ReasoningResult:
        evidence = payload.get("evidence_ids") or []
        confidence = payload.get("confidence")
        return cls(
            unit_id=str(payload["unit_id"]),
            decision=payload["decision"],
            cwe=CWERef.from_dict(payload["cwe"]),
            supporting_source_lines=SourceSpan.from_dict(payload["supporting_source_lines"]),
            root_cause=str(payload["root_cause"]),
            explanation=str(payload["explanation"]),
            remediation=str(payload["remediation"]),
            schema_version=str(payload.get("schema_version") or SCHEMA_VERSION),
            confidence=float(confidence) if confidence is not None else None,
            evidence_ids=tuple(str(item) for item in evidence),
        )
