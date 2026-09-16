import pytest


@pytest.fixture(autouse=True)
def _clear_llm_keys(monkeypatch) -> None:
    """Unit tests never call a live LLM. A developer key in the shell must not leak into pytest."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CWE_VULN_LLM_API_KEY", raising=False)
