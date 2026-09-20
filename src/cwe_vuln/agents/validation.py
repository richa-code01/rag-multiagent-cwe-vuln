"""ValidatorAgent: ApproachDoc stage 5 — deterministic output validation.

Rule-based by design (cheaper and reproducible): schema, CWE-in-KB, cited-line
grounding, and internal consistency. SAST disagreement is a warning, not a
failure — the whole point of the LLM stage is recovering from regex blind spots.
An optional LLM critic ablation lives in cwe_vuln.agents.critic and is never on
the default thesis path.
"""

from __future__ import annotations

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.pipeline import ValidationReport
from cwe_vuln.models.reasoning import ReasoningResult
from cwe_vuln.validator import ResultValidator


class ValidatorAgent:
    name = "validation"

    def __init__(self, validator: ResultValidator | None = None) -> None:
        self._validator = validator or ResultValidator()

    def check(
        self,
        result: ReasoningResult,
        unit: SeedUnit,
        evidence: list[Evidence],
    ) -> ValidationReport:
        return self._validator.check(result, unit, evidence)
