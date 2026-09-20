"""EvidenceAgent: ApproachDoc stage 1 — SAST evidence extraction.

Honest scope: regex-based static signals, not AST/taint analysis. The agent
maps rule matches to Evidence records with 1-based line spans; downstream
agents treat this as a cheap, high-precision-but-incomplete signal.
"""

from __future__ import annotations

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.sast import RegexEvidenceExtractor


class EvidenceAgent:
    name = "evidence"

    def __init__(self, extractor: RegexEvidenceExtractor | None = None) -> None:
        self._extractor = extractor or RegexEvidenceExtractor()

    def extract(self, unit: SeedUnit) -> list[Evidence]:
        return self._extractor.extract(unit)
