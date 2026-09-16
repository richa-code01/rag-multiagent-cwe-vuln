# Cost-aware orchestrator

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

`Pipeline.run(unit)` in `src/cwe_vuln/orchestrator/` wires SAST evidence → hybrid retrieval → reasoner → validator.

Cost policy (here only, not in the thesis title; knobs in `config.Settings`):

- Always run regex SAST first
- `use_llm_if_available` (default True) and `skip_llm_when_sast_hits` (default False)
- No Groq key (`GROQ_API_KEY`; `CWE_VULN_LLM_API_KEY` override) → do **not** construct `LLMReasoner`; `sast_first_skip_llm` / `hybrid_retrieve_skip_llm` + `TemplateReasoner`
- Groq key present → `sast_then_llm` / `hybrid_retrieve_then_llm`, unless `skip_llm_when_sast_hits` and evidence exists
- Default model `llama-3.1-8b-instant`. `OPENAI_API_KEY` is ignored.
- Every unit records `path`, `reasoner`, and `embedder`

`Pipeline` depends on protocols in `orchestrator/ports.py`, not on inlined regexes, CWE text, or prompt blobs.

```bash
uv run pytest tests/orchestrator/test_orchestrator.py
```

Seed-wide CLI: `uv run cwe-vuln-pipeline`.
