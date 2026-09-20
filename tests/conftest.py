import pytest


@pytest.fixture(autouse=True)
def _clear_llm_keys(monkeypatch) -> None:
    """Unit tests never call a live LLM; developer keys/provider env must not leak."""
    for name in (
        "GROQ_API_KEY",
        "OPENAI_API_KEY",
        "TOGETHER_API_KEY",
        "OPENROUTER_API_KEY",
        "FIREWORKS_API_KEY",
        "DEEPSEEK_API_KEY",
        "OLLAMA_API_KEY",
        "CWE_VULN_LLM_API_KEY",
        "CWE_VULN_LLM_PROVIDER",
        "CWE_VULN_LLM_MODEL",
        "CWE_VULN_LLM_BASE_URL",
        "CWE_VULN_LLM_JSON_MODE",
    ):
        monkeypatch.delenv(name, raising=False)
