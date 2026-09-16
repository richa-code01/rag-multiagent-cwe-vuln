"""Map regex rule hits to Evidence records. CWE names/mitigations stay in knowledge."""

from __future__ import annotations

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.sast.detector import RULES


def _line_of(source: str, index: int) -> int:
    return source.count("\n", 0, index) + 1


def _snippet(source: str, start_line: int, end_line: int) -> str:
    lines = source.splitlines()
    return "\n".join(lines[start_line - 1 : end_line])


def extract_evidence(unit: SeedUnit) -> list[Evidence]:
    """Map each regex match to an Evidence record with 1-based line span."""
    found: list[Evidence] = []
    for rule in RULES:
        for match in rule.pattern.finditer(unit.source):
            start_line = _line_of(unit.source, match.start())
            end_line = _line_of(unit.source, match.end())
            found.append(
                Evidence(
                    evidence_id=f"{unit.unit_id}:{rule.rule_id}:{start_line}",
                    rule_id=rule.rule_id,
                    cwe_id=rule.cwe_id,
                    path=unit.path,
                    start_line=start_line,
                    end_line=end_line,
                    snippet=_snippet(unit.source, start_line, end_line),
                    rationale=rule.description,
                )
            )
    return found


class RegexEvidenceExtractor:
    def extract(self, unit: SeedUnit) -> list[Evidence]:
        return extract_evidence(unit)
