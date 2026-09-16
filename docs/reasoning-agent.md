# Reasoning agent

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

`TemplateReasoner.compose(unit, evidence, hits)` in `src/cwe_vuln/reasoner/` builds an Assignment 4 `ReasoningResult`. It does **not** run the pipeline or call an LLM. Constrained composer on the seed. Caller passes units; this package does not load the dataset from disk.

- Evidence present → `vulnerable`, CWE/span from first `Evidence`, description/mitigation from the knowledge store
- Evidence empty → `not_vulnerable`, CWE from top retrieval hit (else the unit label), fallback source span

```bash
uv run pytest tests/reasoner/test_reasoner.py
```

Pipeline CLI is `uv run cwe-vuln-pipeline`. A live LLM reasoner is not implemented.
