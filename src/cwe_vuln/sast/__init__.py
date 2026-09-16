"""Regex SAST detector and evidence extraction. Emits CWE id hints, not encyclopedia text."""

from cwe_vuln.models.evidence import Evidence
from cwe_vuln.sast.detector import (
    RULES,
    Detection,
    DetectedMatch,
    Rule,
    detect,
    llm_detect,
    llm_detector_status,
    match_rules,
)
from cwe_vuln.sast.extract import RegexEvidenceExtractor, extract_evidence

__all__ = [
    "RULES",
    "Detection",
    "DetectedMatch",
    "Evidence",
    "RegexEvidenceExtractor",
    "Rule",
    "detect",
    "extract_evidence",
    "llm_detect",
    "llm_detector_status",
    "match_rules",
]
