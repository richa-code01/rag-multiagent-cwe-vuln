"""Schema + KB id + cited lines + decision vs evidence. No retrieval."""

from __future__ import annotations

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.knowledge import CWEKnowledgeBase
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.pipeline import CheckResult, ValidationReport
from cwe_vuln.models.reasoning import ReasoningResult
from cwe_vuln.schema import is_valid


class ResultValidator:
    """No retrieval here — only checks against unit, KB, and evidence."""

    def __init__(self, kb: CWEKnowledgeBase | None = None) -> None:
        self.kb = kb or CWEKnowledgeBase.load()

    def check(
        self,
        result: ReasoningResult,
        unit: SeedUnit,
        evidence: list[Evidence],
    ) -> ValidationReport:
        checks = (
            self._schema(result),
            self._cwe_in_kb(result),
            self._cited_lines(result, unit),
            self._decision_matches_evidence(result, evidence),
        )
        return ValidationReport(unit_id=unit.unit_id, passed=all(item.passed for item in checks), checks=checks)

    def _schema(self, result: ReasoningResult) -> CheckResult:
        errors = [] if is_valid(result.to_dict()) else ["schema failed"]
        return CheckResult("schema", not errors, "ok" if not errors else errors[0])

    def _cwe_in_kb(self, result: ReasoningResult) -> CheckResult:
        exists = result.cwe.id in self.kb.entries
        return CheckResult("cwe_in_knowledge", exists, result.cwe.id if exists else f"unknown {result.cwe.id}")

    def _cited_lines(self, result: ReasoningResult, unit: SeedUnit) -> CheckResult:
        span = result.supporting_source_lines
        lines = unit.source.splitlines()
        if span.path != unit.path:
            return CheckResult("cited_lines", False, f"path {span.path} != {unit.path}")
        if not (1 <= span.start_line <= span.end_line <= max(len(lines), 1)):
            return CheckResult("cited_lines", False, f"lines {span.start_line}-{span.end_line} out of range")
        excerpt = "\n".join(lines[span.start_line - 1 : span.end_line])
        ok = span.snippet.strip() in excerpt or span.snippet.strip() in unit.source
        return CheckResult("cited_lines", ok, "ok" if ok else "snippet not in cited line range")

    def _decision_matches_evidence(self, result: ReasoningResult, evidence: list[Evidence]) -> CheckResult:
        if result.decision == "uncertain":
            return CheckResult("decision_consistency", True, "uncertain allowed")
        if result.decision == "vulnerable" and not evidence:
            return CheckResult("decision_consistency", False, "vulnerable without SAST evidence")
        if result.decision == "not_vulnerable" and evidence:
            return CheckResult("decision_consistency", False, "not_vulnerable despite SAST evidence")
        return CheckResult("decision_consistency", True, "ok")
