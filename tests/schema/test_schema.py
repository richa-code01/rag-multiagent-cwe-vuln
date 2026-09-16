import json

from cwe_vuln.config import repo_root
from cwe_vuln.schema import (
    SCHEMA_VERSION,
    ReasoningResult,
    is_valid,
    make_validator,
    validate_output,
)


def _sample(name: str) -> dict:
    path = repo_root() / "data" / "schema_samples" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_schema_is_draft_2020_12() -> None:
    validator = make_validator()
    assert validator.schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert SCHEMA_VERSION == "1.0"


def test_valid_samples() -> None:
    for name in ("vulnerable.json", "not_vulnerable.json", "uncertain.json"):
        payload = _sample(name)
        assert payload["decision"] in {"vulnerable", "not_vulnerable", "uncertain"}
        assert is_valid(payload), validate_output(payload)


def test_invalid_sample_is_rejected() -> None:
    payload = _sample("invalid_missing_fields.json")
    errors = validate_output(payload)
    assert errors
    assert not is_valid(payload)


def test_wrong_decision_is_rejected() -> None:
    payload = _sample("vulnerable.json")
    payload["decision"] = "maybe"
    assert not is_valid(payload)


def test_reasoning_result_roundtrip_matches_schema() -> None:
    payload = _sample("vulnerable.json")
    model = ReasoningResult.from_dict(payload)
    dumped = model.to_dict()
    assert dumped["cwe"]["id"] == "CWE-89"
    assert is_valid(dumped)
