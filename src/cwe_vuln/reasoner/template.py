"""Deterministic composer. No LLM and no dataset/pipeline I/O; caller passes units."""

from __future__ import annotations

from typing import Protocol

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.knowledge import CWEEntry, CWEKnowledgeBase
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.reasoning import CWERef, ReasoningResult, SourceSpan
from cwe_vuln.models.retrieval import RankedHit


class Reasoner(Protocol):
    def reason(
        self,
        unit: SeedUnit,
        evidence: list[Evidence],
        hits: list[RankedHit],
    ) -> ReasoningResult: ...


class TemplateReasoner:
    """Deterministic composer. No LLM and no pipeline I/O."""

    def __init__(self, kb: CWEKnowledgeBase | None = None) -> None:
        self.kb = kb or CWEKnowledgeBase.load()
        self.last_backend = "template"

    def reason(
        self,
        unit: SeedUnit,
        evidence: list[Evidence],
        hits: list[RankedHit],
    ) -> ReasoningResult:
        self.last_backend = "template"
        if evidence:
            return self._vulnerable(unit, evidence)
        return self._not_vulnerable(unit, hits)

    def compose(
        self,
        unit: SeedUnit,
        evidence: list[Evidence],
        hits: list[RankedHit],
    ) -> ReasoningResult:
        return self.reason(unit, evidence, hits)

    def _entry(self, cwe_id: str, fallback: str) -> CWEEntry:
        for key in (cwe_id, fallback):
            found = self.kb.entries.get(key)
            if found:
                return found
        raise KeyError(f"No CWE entry for {cwe_id} or {fallback}")

    def _vulnerable(self, unit: SeedUnit, evidence: list[Evidence]) -> ReasoningResult:
        primary = evidence[0]
        entry = self._entry(primary.cwe_id, unit.cwe_id)
        mitigation = entry.mitigations[0].text if entry.mitigations else "See the CWE catalog mitigations."
        return ReasoningResult(
            unit_id=unit.unit_id,
            decision="vulnerable",
            cwe=CWERef(id=entry.id, name=entry.name),
            supporting_source_lines=primary.to_span(),
            root_cause=entry.description,
            explanation=f"SAST rule {primary.rule_id} matched this seed unit. {primary.rationale}",
            remediation=mitigation,
            confidence=0.85,
            evidence_ids=tuple(item.evidence_id for item in evidence),
        )

    def _not_vulnerable(self, unit: SeedUnit, hits: list[RankedHit]) -> ReasoningResult:
        cwe_id = hits[0].cwe_id if hits else unit.cwe_id
        entry = self._entry(cwe_id, unit.cwe_id)
        mitigation = entry.mitigations[0].text if entry.mitigations else "Keep the safe pattern already in this unit."
        return ReasoningResult(
            unit_id=unit.unit_id,
            decision="not_vulnerable",
            cwe=CWERef(id=entry.id, name=entry.name),
            supporting_source_lines=_fallback_span(unit),
            root_cause="No configured SAST rule matched; the unit is treated as the safe counterpart for this CWE family.",
            explanation=(
                "Regex evidence is empty. Hybrid retrieval may still rank a related CWE "
                f"({entry.id}) for explanation context; that is not a vulnerability decision."
            ),
            remediation=mitigation,
            confidence=0.7,
            evidence_ids=(),
        )


def _fallback_span(unit: SeedUnit) -> SourceSpan:
    lines = unit.source.splitlines()
    for index, line in enumerate(lines, start=1):
        text = line.strip()
        if text.startswith(("public ", "return ", "String ", "Path ", "File ", "byte[]")):
            return SourceSpan(path=unit.path, start_line=index, end_line=index, snippet=line)
    snippet = lines[0] if lines else " "
    return SourceSpan(path=unit.path, start_line=1, end_line=1, snippet=snippet)
