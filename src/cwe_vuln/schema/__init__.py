"""JSON Schema load and validate helpers. ReasoningResult type lives in models."""

from cwe_vuln.models.reasoning import SCHEMA_VERSION, CWERef, Decision, ReasoningResult, SourceSpan
from cwe_vuln.schema.contract import is_valid, load_schema, make_validator, schema_path, validate_output

__all__ = [
    "SCHEMA_VERSION",
    "CWERef",
    "Decision",
    "ReasoningResult",
    "SourceSpan",
    "is_valid",
    "load_schema",
    "make_validator",
    "schema_path",
    "validate_output",
]
