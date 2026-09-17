"""Validate reasoning outputs. Schema, KB, cited lines, JSON consistency — not SAST agreement."""

from cwe_vuln.models.pipeline import CheckResult, ValidationReport
from cwe_vuln.validator.checks import ResultValidator

__all__ = ["CheckResult", "ResultValidator", "ValidationReport"]
