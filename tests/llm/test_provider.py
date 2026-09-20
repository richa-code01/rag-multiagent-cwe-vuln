"""LLM provider registry: swap Groq/OpenAI/custom with env, no reasoner changes."""

from cwe_vuln.config import MissingLLMKeyError, require_llm_api_key, settings
from cwe_vuln.llm import (
    OpenAICompatProvider,
    ProviderSpec,
    RateLimitError,
    UnknownProviderError,
    api_key_from_env,
    fallback_models,
    known_providers,
    register_provider,
    resolve_spec,
)
from cwe_vuln.reasoner import LLMReasoner


def test_default_provider_is_groq() -> None:
    spec = resolve_spec()
    assert spec.name == "groq"
    assert spec.base_url.startswith("https://api.groq.com/")
    assert spec.default_model == "openai/gpt-oss-20b"
    assert "GROQ_API_KEY" in spec.key_env


def test_openai_key_ignored_on_groq_provider(monkeypatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("CWE_VULN_LLM_API_KEY", raising=False)
    monkeypatch.delenv("CWE_VULN_LLM_PROVIDER", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-count")
    assert settings.llm_provider() == "groq"
    assert settings.llm_api_key() is None
    assert LLMReasoner.from_env() is None


def test_openai_provider_uses_openai_key(monkeypatch) -> None:
    monkeypatch.setenv("CWE_VULN_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-openai")
    monkeypatch.delenv("CWE_VULN_LLM_MODEL", raising=False)
    monkeypatch.delenv("CWE_VULN_LLM_BASE_URL", raising=False)
    spec = resolve_spec()
    assert spec.name == "openai"
    assert api_key_from_env(spec) == "sk-test-openai"
    provider = OpenAICompatProvider.from_env()
    assert provider is not None
    assert provider.name == "openai"
    assert provider.base_url == "https://api.openai.com/v1"
    assert provider.model == "gpt-4o-mini"
    reasoner = LLMReasoner.from_env()
    assert reasoner is not None
    assert reasoner.provider_name == "openai"
    assert reasoner.model == "gpt-4o-mini"


def test_universal_key_overrides_provider_key(monkeypatch) -> None:
    monkeypatch.setenv("CWE_VULN_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    monkeypatch.setenv("CWE_VULN_LLM_API_KEY", "sk-override")
    assert api_key_from_env() == "sk-override"


def test_custom_provider_needs_base_url_and_model(monkeypatch) -> None:
    monkeypatch.setenv("CWE_VULN_LLM_PROVIDER", "custom")
    monkeypatch.setenv("CWE_VULN_LLM_API_KEY", "tok")
    monkeypatch.delenv("CWE_VULN_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("CWE_VULN_LLM_MODEL", raising=False)
    try:
        OpenAICompatProvider.from_env()
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "custom" in str(exc)


def test_custom_provider_from_env(monkeypatch) -> None:
    monkeypatch.setenv("CWE_VULN_LLM_PROVIDER", "custom")
    monkeypatch.setenv("CWE_VULN_LLM_BASE_URL", "https://llm.internal/v1")
    monkeypatch.setenv("CWE_VULN_LLM_MODEL", "corp-model")
    monkeypatch.setenv("CWE_VULN_LLM_API_KEY", "corp-key")
    provider = OpenAICompatProvider.from_env()
    assert provider is not None
    assert provider.name == "custom"
    assert provider.base_url == "https://llm.internal/v1"
    assert provider.model == "corp-model"
    assert provider.api_key == "corp-key"


def test_ollama_does_not_require_a_key(monkeypatch) -> None:
    monkeypatch.setenv("CWE_VULN_LLM_PROVIDER", "ollama")
    monkeypatch.delenv("CWE_VULN_LLM_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    assert settings.llm_ready()
    provider = OpenAICompatProvider.from_env()
    assert provider is not None
    assert provider.base_url.endswith(":11434/v1")
    key = require_llm_api_key()
    assert key == "ollama"


def test_unknown_provider_raises(monkeypatch) -> None:
    monkeypatch.setenv("CWE_VULN_LLM_PROVIDER", "not-a-vendor")
    try:
        resolve_spec()
        raise AssertionError("expected UnknownProviderError")
    except UnknownProviderError as exc:
        assert "groq" in str(exc)
        assert "openai" in str(exc)


def test_register_provider_is_enough_to_add_a_host(monkeypatch) -> None:
    from cwe_vuln.llm.spec import _PROVIDERS

    register_provider(
        ProviderSpec(
            name="acme",
            base_url="https://acme.example/v1",
            default_model="acme-large",
            key_env=("ACME_API_KEY",),
        )
    )
    monkeypatch.setenv("CWE_VULN_LLM_PROVIDER", "acme")
    monkeypatch.setenv("ACME_API_KEY", "acme-secret")
    try:
        provider = OpenAICompatProvider.from_env()
        assert provider is not None
        assert provider.name == "acme"
        assert provider.model == "acme-large"
        assert "acme" in known_providers()
    finally:
        _PROVIDERS.pop("acme", None)


def test_fallback_models_follow_the_provider(monkeypatch) -> None:
    monkeypatch.delenv("CWE_VULN_LLM_PROVIDER", raising=False)
    assert "openai/gpt-oss-20b" in fallback_models()
    monkeypatch.setenv("CWE_VULN_LLM_PROVIDER", "openai")
    assert "gpt-4o-mini" in fallback_models()


def test_openai_compat_maps_429_to_rate_limit_error(monkeypatch) -> None:
    class FakeRateLimit(Exception):
        status_code = 429

    class BoomCompletions:
        def create(self, **_kwargs):
            raise FakeRateLimit("429 tokens per day")

    class BoomChat:
        def __init__(self) -> None:
            self.completions = BoomCompletions()

    class BoomClient:
        def __init__(self, **_kwargs) -> None:
            self.chat = BoomChat()

    import openai

    captured: dict[str, object] = {}

    class RecordingClient(BoomClient):
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)
            super().__init__(**kwargs)

    monkeypatch.setattr(openai, "OpenAI", RecordingClient)
    provider = OpenAICompatProvider(
        name="groq",
        api_key="gsk-test",
        model="openai/gpt-oss-20b",
        base_url="https://api.groq.com/openai/v1",
    )
    try:
        provider.complete([{"role": "user", "content": "hi"}])
        raise AssertionError("expected RateLimitError")
    except RateLimitError as exc:
        assert exc.status_code == 429
    assert captured.get("timeout") == 90.0
    assert captured.get("max_retries") == 0


def test_reasoner_accepts_an_injected_provider() -> None:
    from cwe_vuln.dataset import load_seed
    from cwe_vuln.llm import ChatResult
    from cwe_vuln.sast import extract_evidence
    from cwe_vuln.schema import is_valid
    import json

    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    payload = {
        "schema_version": "1.0",
        "unit_id": unit.unit_id,
        "decision": "vulnerable",
        "cwe": {"id": "CWE-89", "name": "SQL Injection"},
        "supporting_source_lines": {
            "path": unit.path,
            "start_line": 1,
            "end_line": 1,
            "snippet": unit.source.splitlines()[0],
        },
        "root_cause": "concat",
        "explanation": "sast",
        "remediation": "prepared statement",
    }

    class StubProvider:
        name = "stub"
        model = "stub-model"
        base_url = "https://stub.local/v1"
        api_key = "stub-key"

        def complete(self, messages, *, json_mode=None):
            del messages, json_mode
            return ChatResult(text=json.dumps(payload), provider="stub", model="stub-model", latency_ms=4)

    reasoner = LLMReasoner(provider=StubProvider())
    result = reasoner.reason(unit, extract_evidence(unit), [])
    assert reasoner.provider_name == "stub"
    assert reasoner.model == "stub-model"
    assert reasoner.last_latency_ms == 4
    assert result.decision == "vulnerable"
    assert is_valid(result.to_dict())


def test_missing_key_message_names_the_selected_provider(monkeypatch) -> None:
    monkeypatch.setenv("CWE_VULN_LLM_PROVIDER", "together")
    monkeypatch.delenv("CWE_VULN_LLM_API_KEY", raising=False)
    monkeypatch.delenv("TOGETHER_API_KEY", raising=False)
    try:
        require_llm_api_key()
        raise AssertionError("expected MissingLLMKeyError")
    except MissingLLMKeyError as exc:
        assert "together" in str(exc).lower()
        assert "TOGETHER_API_KEY" in str(exc)
