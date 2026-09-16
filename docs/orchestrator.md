# Cost-aware orchestrator

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

`Pipeline.run(unit)` wires SAST evidence → hybrid retrieval → template reasoner → validator.

Cost policy (here only, not in the thesis title):

- Run regex SAST first
- Skip LLM when SAST evidence is present **or** no API key is set (`CWE_VULN_LLM_API_KEY` / `OPENAI_API_KEY`)
- If a key is present, still use the template reasoner (LLM path is not implemented); `path` records that

`Pipeline` depends on protocols in `ports.py`, not on inlined regexes or CWE text.

```bash
uv run pytest tests/test_orchestrator.py
```

The seed-wide CLI is the next `framework` phase.
