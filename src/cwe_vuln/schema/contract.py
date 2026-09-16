"""Load and validate Assignment 4 reasoning JSON. No agent logic here."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from cwe_vuln.config import repo_root


def schema_path(root: Path | None = None) -> Path:
    return (root or repo_root()) / "schemas" / "reasoning_output.schema.json"


def load_schema(root: Path | None = None) -> dict[str, Any]:
    return json.loads(schema_path(root).read_text(encoding="utf-8"))


def make_validator(root: Path | None = None) -> Draft202012Validator:
    schema = load_schema(root)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_output(payload: dict[str, Any], root: Path | None = None) -> list[str]:
    """Return jsonschema error strings; empty means valid."""
    validator = make_validator(root)
    return [f"{list(err.path) or ['<root>']}: {err.message}" for err in validator.iter_errors(payload)]


def is_valid(payload: dict[str, Any], root: Path | None = None) -> bool:
    return not validate_output(payload, root)
