"""SAST-style regex baseline for the Assignment 1 Java seed.

Rules are pedagogical pattern checks written against this seed. They are not a
production SAST engine and are not evaluated on public benchmarks.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Literal

from cwe_vuln.dataset import SeedUnit

Label = Literal["vulnerable", "not_vulnerable"]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    cwe_id: str
    description: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class Detection:
    unit_id: str
    predicted_label: Label
    predicted_cwes: tuple[str, ...]
    matched_rules: tuple[str, ...]
    notes: str = ""

    @property
    def is_vulnerable(self) -> bool:
        return self.predicted_label == "vulnerable"


# Patterns are intentionally simple and seed-oriented.
RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="sql_string_concat",
        cwe_id="CWE-89",
        description="SQL keyword string concatenated with an identifier (string-built query).",
        pattern=re.compile(
            r'"(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+',
            re.IGNORECASE,
        ),
    ),
    Rule(
        rule_id="html_output_unencoded",
        cwe_id="CWE-79",
        description="HTML markup concatenated with a value that is not passed to htmlEncode().",
        pattern=re.compile(
            r"<(?:div|p|span|html|body)\b[^\n]*\+\s*(?!htmlEncode\s*\()[A-Za-z_]",
            re.IGNORECASE,
        ),
    ),
    Rule(
        rule_id="file_path_concat",
        cwe_id="CWE-22",
        description="java.io.File constructed with string concatenation of a path segment.",
        pattern=re.compile(r"new\s+File\s*\([^;]*\+", re.IGNORECASE),
    ),
    Rule(
        rule_id="java_deserialization",
        cwe_id="CWE-502",
        description="ObjectInputStream and/or readObject on an input stream.",
        pattern=re.compile(r"\bObjectInputStream\b|\.readObject\s*\("),
    ),
    Rule(
        rule_id="hardcoded_secret_literal",
        cwe_id="CWE-798",
        description="password / apiKey / secret assigned a string literal.",
        pattern=re.compile(
            r"""\b(?:password|passwd|api[_-]?key|secret)\s*=\s*["'][^"']+["']""",
            re.IGNORECASE,
        ),
    ),
    Rule(
        rule_id="weak_crypto_algorithm",
        cwe_id="CWE-327",
        description="MessageDigest/Cipher getInstance using MD5, DES, RC4, or SHA-1.",
        pattern=re.compile(
            r'getInstance\s*\(\s*"(?:MD5|DES|DESede|RC4|SHA-1|SHA1)"\s*\)',
            re.IGNORECASE,
        ),
    ),
)


@dataclass
class DetectedMatch:
    rule_id: str
    cwe_id: str


def match_rules(source: str) -> list[DetectedMatch]:
    found: list[DetectedMatch] = []
    for rule in RULES:
        if rule.pattern.search(source):
            found.append(DetectedMatch(rule_id=rule.rule_id, cwe_id=rule.cwe_id))
    return found


def detect(unit: SeedUnit) -> Detection:
    """Run the regex baseline on one labeled unit."""
    matches = match_rules(unit.source)
    cwes = tuple(dict.fromkeys(item.cwe_id for item in matches))
    rule_ids = tuple(item.rule_id for item in matches)
    if matches:
        return Detection(
            unit_id=unit.unit_id,
            predicted_label="vulnerable",
            predicted_cwes=cwes,
            matched_rules=rule_ids,
            notes="regex baseline matched one or more SAST-style patterns",
        )
    return Detection(
        unit_id=unit.unit_id,
        predicted_label="not_vulnerable",
        predicted_cwes=(),
        matched_rules=(),
        notes="regex baseline matched no configured patterns",
    )


def llm_detect(source: str) -> Detection | None:
    """Optional LLM detector stub.

    Assignment 1 does not call a model. If no API key is present the stub is
    skipped. If a key is present it still returns None — the model-backed
    detector is future work, not part of this baseline.
    """
    del source  # unused in the Assignment 1 stub
    key = os.environ.get("CWE_VULN_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key:
        return None
    return None


def llm_detector_status() -> str:
    key = os.environ.get("CWE_VULN_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key:
        return "skipped_no_api_key"
    return "skipped_not_implemented_in_assignment_1"
