"""Agent-facing protocols. Implementations live in sibling modules."""

from __future__ import annotations

from typing import Protocol

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.evidence import Evidence


class EvidenceExtractor(Protocol):
    def extract(self, unit: SeedUnit) -> list[Evidence]: ...
