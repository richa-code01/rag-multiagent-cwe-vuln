# Reasoning agent

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

`Reasoner.reason(unit, evidence, hits)` in `src/cwe_vuln/reasoner/` builds an Assignment 4 `ReasoningResult`. The package does **not** run the pipeline or load the dataset from disk. Caller passes units.

Two implementations share the port:

- `TemplateReasoner` — deterministic offline default. Evidence present → `vulnerable`; empty evidence → `not_vulnerable`. `compose()` is kept as an alias.
- `LLMReasoner` — OpenAI-compatible chat completion. Constructed only when `GROQ_API_KEY` (or `CWE_VULN_LLM_API_KEY` override) is set (`LLMReasoner.from_env()` otherwise returns `None`). Optional `CWE_VULN_LLM_MODEL` (default `openai/gpt-oss-20b`) and `CWE_VULN_LLM_BASE_URL`. Prompt asks for A4 JSON only (detection/explanation; no exploit generation). Invalid JSON is retried once, then the template is used (`reasoner=llm_fallback_template`).

```bash
uv run pytest tests/reasoner/test_reasoner.py tests/reasoner/test_llm.py
```

Tests mock the SDK client. They do not call Groq. Pipeline CLI is `uv run cwe-vuln-pipeline`. Tomorrow: `export GROQ_API_KEY=...`
