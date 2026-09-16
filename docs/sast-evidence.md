# SAST evidence extraction

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

Turns Assignment 1 regex matches into structured `Evidence` objects later agents can consume. Not the reasoning agent.

## Boundary

- `src/cwe_vuln/detector.py` — rule patterns + binary `detect()`
- `src/cwe_vuln/evidence.py` — `Evidence` dataclass + `extract_evidence(unit)`
- `src/cwe_vuln/ports.py` — `EvidenceExtractor` protocol

Each `Evidence` has: `evidence_id`, `rule_id`, `cwe_id`, `path`, `start_line`, `end_line`, `snippet`, `rationale`. Line numbers are 1-based from the Java file. CWE names/mitigations still live in `knowledge`, not here.

```bash
uv run cwe-vuln-evidence --unit-id java_cwe89_sqli_concat
uv run pytest tests/test_evidence.py
```

Safe seed units should print an empty `evidence` list. Vulnerable units should include a snippet that contains the teaching pattern (for example `SELECT` concat for CWE-89).
