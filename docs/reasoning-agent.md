# Reasoning agent

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

`TemplateReasoner.compose(unit, evidence, hits)` builds an Assignment 4 `ReasoningResult`. It does **not** run the pipeline or call an LLM. Constrained composer on the seed.

- Evidence present → `vulnerable`, CWE/span from first `Evidence`, description/mitigation from the knowledge store
- Evidence empty → `not_vulnerable`, CWE from top retrieval hit (else the unit label), fallback source span

```bash
uv run pytest tests/test_reasoner.py
```

Pipeline CLI comes with the orchestrator/framework. This module has no file-walking of its own.
