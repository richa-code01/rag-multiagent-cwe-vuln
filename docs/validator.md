# Validator

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

`ResultValidator.check(result, unit, evidence)` in `src/cwe_vuln/validator/` records pass/fail. It does not retrieve.

Checks (all must pass for `report.passed`):

1. Assignment 4 JSON Schema
2. `cwe.id` exists in the curated knowledge store
3. Cited `path`/`start_line`/`end_line`/`snippet` exist in the Java unit
4. Internal JSON consistency (`unit_id` matches, decision enum, CWE id format, non-empty prose, confidence in `[0, 1]`)

SAST agreement is **not** a failing check. Groq may call a unit `vulnerable` when regex evidence is empty (FN traps). That is recorded as a `sast_disagreement` **warning** and does not fail the unit.

The previous “vulnerable iff SAST evidence non-empty” rule made the validator pass 2/24 when Groq correctly caught SAST false negatives. That contract is retired.

```bash
uv run pytest tests/validator/test_validator.py
```
