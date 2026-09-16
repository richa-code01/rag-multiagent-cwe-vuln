"""Turn regex rule hits into structured SAST evidence (file, lines, snippet)."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass

from cwe_vuln.dataset import SeedUnit, load_seed
from cwe_vuln.detector import RULES
from cwe_vuln.schema import SourceSpan


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract SAST evidence objects from seed Java units.")
    parser.add_argument("--unit-id", dest="unit_id", default=None)
    args = parser.parse_args(argv)
    units = load_seed()
    if args.unit_id:
        units = [unit for unit in units if unit.unit_id == args.unit_id]
        if not units:
            print(f"unknown unit_id {args.unit_id}")
            return 1
    payload = [
        {"unit_id": unit.unit_id, "evidence": [item.to_dict() for item in extract_evidence(unit)]}
        for unit in units
    ]
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
