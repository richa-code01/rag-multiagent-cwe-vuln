# Validator

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

`ResultValidator.check(result, unit, evidence)` in `src/cwe_vuln/validator/` records pass/fail. It does not retrieve.

Checks:

1. Assignment 4 JSON Schema
2. `cwe.id` exists in the curated knowledge store
3. Cited `path`/`start_line`/`end_line`/`snippet` exist in the Java unit
4. Decision consistency: `vulnerable` requires SAST evidence; `not_vulnerable` requires none; `uncertain` is allowed

```bash
uv run pytest tests/validator/test_validator.py
```
