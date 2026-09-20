import json

from cwe_vuln.config import DEFAULT_LLM_BASE_URL, DEFAULT_LLM_MODEL, settings
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


def test_require_llm_api_key_raises_without_key(monkeypatch) -> None:
    from cwe_vuln.config import MissingLLMKeyError, require_llm_api_key

    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("CWE_VULN_LLM_API_KEY", raising=False)
    try:
        require_llm_api_key()
        raise AssertionError("expected MissingLLMKeyError")
    except MissingLLMKeyError as exc:
        assert "GROQ_API_KEY" in str(exc)


def test_from_env_without_key_returns_none(monkeypatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("CWE_VULN_LLM_API_KEY", raising=False)
    assert LLMReasoner.from_env() is None


def test_openai_api_key_is_ignored_on_default_groq_provider(monkeypatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("CWE_VULN_LLM_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-count")
    assert settings.llm_provider() == "groq"
    assert settings.llm_api_key() is None
    assert LLMReasoner.from_env() is None


def test_groq_defaults_and_override_key(monkeypatch) -> None:
    monkeypatch.delenv("CWE_VULN_LLM_MODEL", raising=False)
    monkeypatch.delenv("CWE_VULN_LLM_BASE_URL", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "gsk-primary")
    monkeypatch.setenv("CWE_VULN_LLM_API_KEY", "gsk-override")
    assert DEFAULT_LLM_MODEL == "openai/gpt-oss-20b"
    assert DEFAULT_LLM_BASE_URL == "https://api.groq.com/openai/v1"
    assert settings.llm_api_key() == "gsk-override"
    reasoner = LLMReasoner.from_env()
    assert reasoner is not None
    assert reasoner.model == "openai/gpt-oss-20b"
    assert reasoner.base_url == "https://api.groq.com/openai/v1"
    assert reasoner.api_key == "gsk-override"
    assert reasoner.provider_name == "groq"


def test_llm_reasoner_with_mocked_client_is_schema_valid() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    payload = _valid_payload(unit.unit_id)

    def complete(_messages: list[dict[str, str]]) -> str:
        return json.dumps(payload)

    reasoner = LLMReasoner(api_key="gsk-test", complete=complete)
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

    reasoner = LLMReasoner(api_key="gsk-test", complete=complete)
    result = reasoner.reason(unit, extract_evidence(unit), [])
    assert calls["n"] == 2
    assert reasoner.last_backend == "llm_fallback_template"
    assert result.decision == "vulnerable"
    assert is_valid(result.to_dict())
    template = TemplateReasoner().reason(unit, extract_evidence(unit), [])
    assert result.decision == template.decision
    assert result.cwe.id == template.cwe.id


def test_normalize_keeps_model_citation_and_normalizes_path() -> None:
    from cwe_vuln.validator import ResultValidator

    unit = next(item for item in load_seed() if item.unit_id == "java_cwe798_env_config")
    payload = {
        "schema_version": "1.0",
        "unit_id": unit.unit_id,
        "decision": "not_vulnerable",
        "cwe": {"id": "CWE-798", "name": "Use of Hard-coded Credentials"},
        "supporting_source_lines": {
            "path": "wrong/path.java",
            "start_line": 12,
            "end_line": 13,
            "snippet": '        String username = System.getenv("APP_USERNAME");\n        String password = System.getenv("APP_PASSWORD");',
        },
        "root_cause": "Credentials come from the environment.",
        "explanation": "No hardcoded password literal.",
        "remediation": "Keep using environment variables.",
        "confidence": 0.9,
        "extra_ignored": "drop me",
    }

    def complete(_messages: list[dict[str, str]]) -> str:
        return json.dumps(payload)

    reasoner = LLMReasoner(api_key="gsk-test", complete=complete)
    result = reasoner.reason(unit, [], [])
    assert reasoner.last_backend == "llm"
    # Path echo is normalized (we hand it to the model); the snippet is NOT substituted.
    assert result.supporting_source_lines.path == unit.path
    assert result.supporting_source_lines.snippet == payload["supporting_source_lines"]["snippet"]
    assert is_valid(result.to_dict())
    report = ResultValidator().check(result, unit, [])
    assert report.passed


def test_wrong_snippet_fails_cited_lines_instead_of_silent_rewrite() -> None:
    from cwe_vuln.validator import ResultValidator

    unit = next(item for item in load_seed() if item.unit_id == "java_cwe798_env_config")
    payload = {
        "schema_version": "1.0",
        "unit_id": unit.unit_id,
        "decision": "not_vulnerable",
        "cwe": {"id": "CWE-798", "name": "Use of Hard-coded Credentials"},
        "supporting_source_lines": {
            "path": unit.path,
            "start_line": 12,
            "end_line": 13,
            "snippet": "this snippet was hallucinated and is not in the source",
        },
        "root_cause": "Credentials come from the environment.",
        "explanation": "No hardcoded password literal.",
        "remediation": "Keep using environment variables.",
    }

    def complete(_messages: list[dict[str, str]]) -> str:
        return json.dumps(payload)

    reasoner = LLMReasoner(api_key="gsk-test", complete=complete)
    result = reasoner.reason(unit, [], [])
    assert reasoner.last_backend == "llm"  # schema-valid; citation honesty is the validator's job
    report = ResultValidator().check(result, unit, [])
    cited = next(check for check in report.checks if check.name == "cited_lines")
    assert not cited.passed
    assert not report.passed


def test_unknown_cwe_is_clamped_to_top_hit() -> None:
    from cwe_vuln.models.retrieval import RankedHit
    from cwe_vuln.validator import ResultValidator

    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    payload = _valid_payload(unit.unit_id)
    payload["cwe"] = {"id": "CWE-0", "name": "Unknown"}
    hits = [RankedHit(cwe_id="CWE-89", score=1.0, name="SQL Injection", passage="")]

    def complete(_messages: list[dict[str, str]]) -> str:
        return json.dumps(payload)

    reasoner = LLMReasoner(api_key="gsk-test", complete=complete)
    result = reasoner.reason(unit, extract_evidence(unit), hits)
    assert result.cwe.id == "CWE-89"
    assert result.cwe.name
    assert reasoner.last_cwe_clamped_from == "CWE-0"
    report = ResultValidator().check(result, unit, extract_evidence(unit))
    names = {check.name: check.passed for check in report.checks}
    assert names["cwe_in_knowledge"] is True


def test_rate_limit_is_reraised_not_template_fallback() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")

    class FakeRateLimitError(Exception):
        status_code = 429

    def complete(_messages: list[dict[str, str]]) -> str:
        raise FakeRateLimitError("429 Too Many Requests: tokens per day exceeded")

    reasoner = LLMReasoner(api_key="gsk-test", complete=complete)
    try:
        reasoner.reason(unit, extract_evidence(unit), [])
        raise AssertionError("expected the rate limit error to propagate")
    except FakeRateLimitError:
        pass
    assert reasoner.last_backend != "llm_fallback_template" or reasoner.fallback_reason is None


def test_fallback_reason_and_attempts_recorded() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")

    def complete(_messages: list[dict[str, str]]) -> str:
        return "not json at all"

    reasoner = LLMReasoner(api_key="gsk-test", complete=complete)
    result = reasoner.reason(unit, extract_evidence(unit), [])
    assert reasoner.last_backend == "llm_fallback_template"
    assert reasoner.n_attempts == 2
    assert reasoner.fallback_reason
    assert "ValueError" in reasoner.fallback_reason or "JSON" in reasoner.fallback_reason
    assert result.decision == "vulnerable"  # template decision on a unit with evidence


def test_invalid_then_valid_json_uses_retry() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    payload = _valid_payload(unit.unit_id)
    calls = {"n": 0}

    def complete(_messages: list[dict[str, str]]) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            return "```text\nstill not json\n```"
        return "```json\n" + json.dumps(payload) + "\n```"

    reasoner = LLMReasoner(api_key="gsk-test", complete=complete)
    result = reasoner.reason(unit, extract_evidence(unit), [])
    assert calls["n"] == 2
    assert reasoner.last_backend == "llm"
    assert is_valid(result.to_dict())
