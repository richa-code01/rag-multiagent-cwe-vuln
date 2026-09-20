"""Schema + KB id + cited lines + JSON consistency. SAST disagreement is a warning."""

from __future__ import annotations

import re

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.knowledge import CWEKnowledgeBase
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.pipeline import CheckResult, ValidationReport
from cwe_vuln.models.reasoning import ReasoningResult
from cwe_vuln.schema import is_valid

_CWE_ID = re.compile(r"^CWE-\d+$")
_ALLOWED_DECISIONS = {"vulnerable", "not_vulnerable", "uncertain"}


def _indent_normalize(text: str) -> str:
    return "\n".join(line.strip() for line in text.splitlines())


class ResultValidator:
    """No retrieval here — only checks against unit, KB, and JSON consistency.

    SAST evidence is a signal, not a gold decision. Groq may call a unit
    vulnerable when regex evidence is empty (FN traps). That is a warning,
    not a failed check.
    """

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
            self._cited_lines_normalized(result, unit),
            self._internal_consistency(result, unit),
        )
        warning = self._sast_disagreement(result, evidence)
        warnings = (warning,) if warning is not None else ()
        return ValidationReport(
            unit_id=unit.unit_id,
            passed=all(item.passed for item in checks),
            checks=checks,
            warnings=warnings,
        )

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

    def _cited_lines_normalized(self, result: ReasoningResult, unit: SeedUnit) -> CheckResult:
        """Same range check as ``cited_lines``, but leading whitespace per line is ignored.

        Spans are never rewritten. A pass here with a raw fail is indent-only mismatch.
        """
        span = result.supporting_source_lines
        lines = unit.source.splitlines()
        if span.path != unit.path:
            return CheckResult("cited_lines_normalized", False, f"path {span.path} != {unit.path}")
        if not (1 <= span.start_line <= span.end_line <= max(len(lines), 1)):
            return CheckResult(
                "cited_lines_normalized",
                False,
                f"lines {span.start_line}-{span.end_line} out of range",
            )
        excerpt = _indent_normalize("\n".join(lines[span.start_line - 1 : span.end_line]))
        snippet = _indent_normalize(span.snippet)
        source_n = _indent_normalize(unit.source)
        ok = bool(snippet) and (snippet in excerpt or snippet in source_n)
        return CheckResult(
            "cited_lines_normalized",
            ok,
            "ok" if ok else "snippet not in cited line range after indent normalize",
        )

    def _internal_consistency(self, result: ReasoningResult, unit: SeedUnit) -> CheckResult:
        errors: list[str] = []
        if result.unit_id != unit.unit_id:
            errors.append(f"unit_id {result.unit_id} != {unit.unit_id}")
        if result.decision not in _ALLOWED_DECISIONS:
            errors.append(f"unknown decision {result.decision}")
        if not _CWE_ID.fullmatch(result.cwe.id):
            errors.append(f"malformed cwe id {result.cwe.id}")
        if not result.cwe.name.strip():
            errors.append("empty cwe name")
        for field in ("root_cause", "explanation", "remediation"):
            if not str(getattr(result, field)).strip():
                errors.append(f"empty {field}")
        if result.confidence is not None and not (0.0 <= result.confidence <= 1.0):
            errors.append(f"confidence {result.confidence} out of [0, 1]")
        span = result.supporting_source_lines
        if span.start_line > span.end_line:
            errors.append("start_line > end_line")
        return CheckResult(
            "internal_consistency",
            not errors,
            "ok" if not errors else "; ".join(errors),
        )

    def _sast_disagreement(self, result: ReasoningResult, evidence: list[Evidence]) -> CheckResult | None:
        if result.decision == "uncertain":
            return None
        if result.decision == "vulnerable" and not evidence:
            return CheckResult("sast_disagreement", True, "vulnerable with empty SAST evidence")
        if result.decision == "not_vulnerable" and evidence:
            return CheckResult("sast_disagreement", True, "not_vulnerable despite SAST evidence")
        return None
