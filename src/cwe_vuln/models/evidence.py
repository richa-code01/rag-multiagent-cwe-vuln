"""One Evidence type for SAST hits consumed by retrieval, reasoner, and validator."""

from __future__ import annotations

from dataclasses import dataclass

from cwe_vuln.models.reasoning import SourceSpan


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    rule_id: str
    cwe_id: str
    path: str
    start_line: int
    end_line: int
    snippet: str
    rationale: str

    def to_span(self) -> SourceSpan:
        return SourceSpan(
            path=self.path,
            start_line=self.start_line,
            end_line=self.end_line,
            snippet=self.snippet,
        )

    def to_dict(self) -> dict[str, str | int]:
        return {
            "evidence_id": self.evidence_id,
            "rule_id": self.rule_id,
            "cwe_id": self.cwe_id,
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "snippet": self.snippet,
            "rationale": self.rationale,
        }
