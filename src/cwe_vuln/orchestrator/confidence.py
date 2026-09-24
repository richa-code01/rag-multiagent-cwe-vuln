"""Confidence fusion (ApproachDoc stage 6) and routing risk heuristics.

Weights are fixed, documented, and NOT calibrated on any benchmark — the thesis
reports the fused score as an interpretable heuristic, not a calibrated
probability. Calibration plots would require a held-out split we do not have.
"""

from __future__ import annotations

from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.pipeline import ValidationReport
from cwe_vuln.models.reasoning import ReasoningResult

# Documented fusion weights (sum to 1.0).
W_LLM = 0.45
W_RETRIEVAL = 0.25
W_SAST_AGREE = 0.20
W_VALIDATOR = 0.10


def risk_score(evidence: list[Evidence]) -> float:
    """Prior that the unit is risky, from regex evidence count only.

    0 hits -> 0.0, 1 -> 0.5, 2 -> 0.75, 3 -> 0.875, ... (diminishing returns).
    """
    return round(1.0 - 0.5 ** len(evidence), 4)


def sast_agreement(decision: str, evidence: list[Evidence]) -> float:
    """1.0 when the decision agrees with the SAST signal, 0.3 on contradiction."""
    if decision == "uncertain":
        return 0.5
    if decision == "vulnerable":
        return 1.0 if evidence else 0.3
    return 0.3 if evidence else 1.0


def fuse_confidence(
    result: ReasoningResult,
    evidence: list[Evidence],
    retrieval_confidence: float,
    report: ValidationReport,
) -> float:
    """Weighted fusion of LLM self-confidence, retrieval match, SAST agreement,
    and validator outcome. LLM confidence defaults to 0.5 when absent."""
    llm_conf = result.confidence if result.confidence is not None else 0.5
    validator_score = 1.0 if report.passed else 0.4
    fused = (
        W_LLM * llm_conf
        + W_RETRIEVAL * retrieval_confidence
        + W_SAST_AGREE * sast_agreement(result.decision, evidence)
        + W_VALIDATOR * validator_score
    )
    return round(min(1.0, max(0.0, fused)), 4)
