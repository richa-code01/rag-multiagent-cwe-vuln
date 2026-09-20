# Reasoning agent

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

`Reasoner.reason(unit, evidence, hits)` in `src/cwe_vuln/reasoner/` builds an Assignment 4 `ReasoningResult`. The package does **not** run the pipeline or load the dataset from disk. Caller passes units.

Two implementations share the port:

- `LLMReasoner` — live default. Talks to `cwe_vuln.llm.ChatProvider` (OpenAI-compatible). Groq is the default preset; switch with `CWE_VULN_LLM_PROVIDER` (`openai`, `together`, `ollama`, `custom`, …) plus `CWE_VULN_LLM_MODEL` / `CWE_VULN_LLM_BASE_URL` / the provider key. Prompt asks for A4 JSON only (detection/explanation; no exploit generation). Invalid JSON is retried once, then the template is used (`reasoner=llm_fallback_template`). Rate limits are re-raised.
- `TemplateReasoner` — deterministic **ablation**. Evidence present → `vulnerable`; empty evidence → `not_vulnerable`. Used by `Pipeline.offline()` / `--ablation template`. Scored F1=0 on the 24-unit research split; not the system of record. `compose()` is kept as an alias.

```bash
uv run pytest tests/reasoner/test_reasoner.py tests/reasoner/test_llm.py
```

Tests mock the SDK client. They do not call a live LLM. Pipeline CLI is `uv run cwe-vuln-pipeline` (requires a configured provider; Groq `GROQ_API_KEY` by default).
