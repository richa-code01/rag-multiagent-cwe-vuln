import json

from cwe_vuln.config import settings
from cwe_vuln.dataset import load_seed
from cwe_vuln.reasoner import LLMReasoner, TemplateReasoner
from cwe_vuln.sast import extract_evidence
from cwe_vuln.schema import is_valid


def _valid_payload(unit_id: str = "java_cwe89_sqli_concat") -> dict:
    return {
        "schema_version": "1.0",
        "unit_id": unit_id,
        "decision": "vulnerable",
        "cwe": {"id": "CWE-89", "name": "SQL Injection"},
        "supporting_source_lines": {
            "path": "data/seed/java/CWE89_SqlConcat.java",
            "start_line": 10,
            "end_line": 10,
            "snippet": 'String query = "SELECT * FROM users WHERE name=" + name;',
        },
        "root_cause": "Query string concatenated with untrusted input.",
        "explanation": "SAST evidence shows string-built SQL sent to a statement.",
        "remediation": "Use a parameterized query / PreparedStatement.",
        "confidence": 0.8,
        "evidence_ids": ["java_cwe89_sqli_concat:sql_string_concat:10"],
    }


def test_from_env_without_key_returns_none(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CWE_VULN_LLM_API_KEY", raising=False)
    assert LLMReasoner.from_env() is None


def test_openai_api_key_is_used(monkeypatch) -> None:
    monkeypatch.delenv("CWE_VULN_LLM_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    assert settings.llm_api_key() == "sk-test"
    reasoner = LLMReasoner.from_env()
    assert reasoner is not None
    assert reasoner.api_key == "sk-test"
    assert reasoner.model == "gpt-4o-mini"
    assert reasoner.base_url is None


def test_project_key_overrides_openai_key(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    monkeypatch.setenv("CWE_VULN_LLM_API_KEY", "sk-project")
    assert settings.llm_api_key() == "sk-project"


def test_llm_reasoner_with_mocked_client_is_schema_valid() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    payload = _valid_payload(unit.unit_id)

    def complete(_messages: list[dict[str, str]]) -> str:
        return json.dumps(payload)

    reasoner = LLMReasoner(api_key="sk-test", complete=complete)
    result = reasoner.reason(unit, extract_evidence(unit), [])
    assert result.decision == "vulnerable"
    assert result.cwe.id == "CWE-89"
    assert is_valid(result.to_dict())
    assert reasoner.last_backend == "llm"


def test_invalid_json_retries_then_falls_back_to_template() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    calls = {"n": 0}

    def complete(_messages: list[dict[str, str]]) -> str:
        calls["n"] += 1
        return "not json at all"

    reasoner = LLMReasoner(api_key="sk-test", complete=complete)
    result = reasoner.reason(unit, extract_evidence(unit), [])
    assert calls["n"] == 2
    assert reasoner.last_backend == "llm_fallback_template"
    assert result.decision == "vulnerable"
    assert is_valid(result.to_dict())
    template = TemplateReasoner().reason(unit, extract_evidence(unit), [])
    assert result.decision == template.decision
    assert result.cwe.id == template.cwe.id


def test_invalid_then_valid_json_uses_retry() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    payload = _valid_payload(unit.unit_id)
    calls = {"n": 0}

    def complete(_messages: list[dict[str, str]]) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            return "```text\nstill not json\n```"
        return "```json\n" + json.dumps(payload) + "\n```"

    reasoner = LLMReasoner(api_key="sk-test", complete=complete)
    result = reasoner.reason(unit, extract_evidence(unit), [])
    assert calls["n"] == 2
    assert reasoner.last_backend == "llm"
    assert is_valid(result.to_dict())
