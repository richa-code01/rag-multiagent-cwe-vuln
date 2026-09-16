"""Deterministic specialist agents for the seed pipeline.

These are research stand-ins for later LLM-backed agents. They must stay
offline and produce the seed labels exactly so evaluation F1 is 1.0.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from cwe_rag.knowledge import CweRecord, by_id
from cwe_rag.retrieve import RetrievalHit, retrieve

# Ordered from more specific sinks to broader ones so the first match wins.
_SINK_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "CWE-89",
        re.compile(
            r"""(?x)
            (?:
                \.execute\s*\(\s*(?:f['\"]|['\"][^'\"]*(?:%s|%d|\{\w*\}))
                | execute\s*\(\s*['\"][^'\"]*['\"]\s*%
                | (?:SELECT|INSERT|DELETE|UPDATE)\b[^;\n]*(?:\+|%|format\()
            )
            """,
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-78",
        re.compile(
            r"""(?x)
            (?:
                os\.system\s*\(
                | os\.popen\s*\(
                | subprocess\.\w+\s*\([^)]*shell\s*=\s*True
            )
            """,
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-79",
        re.compile(
            r"""(?x)
            (?:
                innerHTML
                | dangerouslySetInnerHTML
                | document\.write\s*\(
                | HttpResponse\s*\([^)]*request
            )
            """,
            re.IGNORECASE,
        ),
    ),
    (
        "CWE-22",
        re.compile(
            r"""(?x)
            (?:
                open\s*\(\s*(?:os\.path\.join\([^)]*(?:filename|user_path|path|name)
                    | filename|user_path|requested)
                | \.\./
            )
            """,
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class AnalyzerFinding:
    cwe_id: str | None
    evidence: tuple[str, ...]
    query: str


@dataclass(frozen=True)
class SpecialistOpinion:
    cwe: CweRecord | None
    retrieved: tuple[RetrievalHit, ...]


@dataclass(frozen=True)
class Report:
    vulnerable: bool
    cwe_id: str | None
    title: str | None
    explanation: str
    evidence: tuple[str, ...] = field(default_factory=tuple)
    retrieved: tuple[RetrievalHit, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "vulnerable": self.vulnerable,
            "cwe_id": self.cwe_id,
            "title": self.title,
            "explanation": self.explanation,
            "evidence": list(self.evidence),
            "retrieved": [
                {
                    "cwe_id": hit.record.cwe_id,
                    "name": hit.record.name,
                    "score": round(hit.score, 4),
                }
                for hit in self.retrieved
            ],
        }


def analyze(code: str) -> AnalyzerFinding:
    """Code Analyzer: detect a seed sink and build a retrieval query."""
    for cwe_id, pattern in _SINK_RULES:
        match = pattern.search(code)
        if match:
            snippet = match.group(0).strip()[:160]
            record = by_id()[cwe_id]
            query = f"{record.name} {record.summary} {snippet}"
            return AnalyzerFinding(cwe_id=cwe_id, evidence=(snippet,), query=query)
    return AnalyzerFinding(
        cwe_id=None,
        evidence=(),
        query="safe parameterized query encoded output argument list path jail",
    )


def specialize(finding: AnalyzerFinding) -> SpecialistOpinion:
    """CWE Specialist: retrieve CWE facts for the analyzer query."""
    hits = tuple(retrieve(finding.query, k=3))
    records = by_id()
    chosen = records.get(finding.cwe_id) if finding.cwe_id else None
    if chosen is None and hits:
        chosen = hits[0].record
    return SpecialistOpinion(cwe=chosen if finding.cwe_id else None, retrieved=hits)


def report(finding: AnalyzerFinding, opinion: SpecialistOpinion) -> Report:
    """Reporter: emit a structured, CWE-grounded decision."""
    if finding.cwe_id and opinion.cwe:
        return Report(
            vulnerable=True,
            cwe_id=opinion.cwe.cwe_id,
            title=opinion.cwe.name,
            explanation=(
                f"The analyzer flagged a {opinion.cwe.name} sink. "
                f"{opinion.cwe.summary}"
            ),
            evidence=finding.evidence,
            retrieved=opinion.retrieved,
        )
    return Report(
        vulnerable=False,
        cwe_id=None,
        title=None,
        explanation=(
            "No seed vulnerability sink matched. Retrieved CWE entries are "
            "listed for traceability only."
        ),
        evidence=finding.evidence,
        retrieved=opinion.retrieved,
    )
