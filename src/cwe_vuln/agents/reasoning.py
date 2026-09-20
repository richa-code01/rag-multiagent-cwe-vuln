"""ReasoningAgent: ApproachDoc stage 4 — schema-bound LLM composition.

Wraps a UnitReasoner backend (LLMReasoner live, TemplateReasoner for offline
ablations) and passes through the diagnostics the evaluation layer records
(backend used, fallback reason, attempts, token usage, latency).
"""

from __future__ import annotations

from typing import Any

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.reasoning import ReasoningResult
from cwe_vuln.models.retrieval import RankedHit


class ReasoningAgent:
    name = "reasoning"

    def __init__(self, backend: Any) -> None:
        self.backend = backend

    def reason(
        self,
        unit: SeedUnit,
        evidence: list[Evidence],
        hits: list[RankedHit],
    ) -> ReasoningResult:
        return self.backend.reason(unit, evidence, hits)

    def __getattr__(self, item: str):
        # Diagnostics passthrough: last_backend, fallback_reason, last_usage, ...
        return getattr(self.backend, item)
