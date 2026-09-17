# Cost-aware orchestrator

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

`Pipeline.run(unit)` in `src/cwe_vuln/orchestrator/` wires SAST evidence → hybrid retrieval → reasoner → validator.

SAST is **evidence extraction**, not the final vulnerability decision. The live default reasoner is Groq `LLMReasoner`.

Cost policy (here only, not in the thesis title; knobs in `config.Settings`):

- Always run regex SAST first (signals for retrieval + the reasoner)
- `Pipeline.default()` **requires** `GROQ_API_KEY` (or `CWE_VULN_LLM_API_KEY`); missing key raises `MissingLLMKeyError`
- Default knobs: `use_llm_if_available=True`, `skip_llm_when_sast_hits=False`
- Default paths: `sast_then_llm` / `hybrid_retrieve_then_llm`
- `Pipeline.offline()` / `cwe-vuln-pipeline --offline` uses `TemplateReasoner` for paper contrast (F1=0 on research_test; not the system of record)
- `--ablation skip-llm` keeps the old cost path (SAST hits → template) as an opt-in trial
- Default model `openai/gpt-oss-20b`. `OPENAI_API_KEY` is ignored.
- Every unit records `path`, `reasoner`, and `embedder`

`Pipeline` depends on protocols in `orchestrator/ports.py`, not on inlined regexes, CWE text, or prompt blobs.

```bash
uv run pytest tests/orchestrator/test_orchestrator.py
```

Seed-wide CLI: `uv run cwe-vuln-pipeline` (requires Groq). Ablation: `uv run cwe-vuln-pipeline --offline`.
