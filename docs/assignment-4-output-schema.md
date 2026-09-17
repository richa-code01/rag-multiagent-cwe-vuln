# Assignment 4: structured reasoning output schema

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

Schema **before** the reasoning agent. This PR does not implement the agent.

## Schema

- File: `schemas/reasoning_output.schema.json`
- Dialect: JSON Schema Draft 2020-12
- Python: `src/cwe_vuln/schema/` (`jsonschema.Draft202012Validator`)
- `schema_version` const: `1.0`

Required fields:

| Field | Meaning |
| --- | --- |
| `decision` | `vulnerable` \| `not_vulnerable` \| `uncertain` |
| `cwe` | `{id, name}` with `id` matching `CWE-[0-9]+` |
| `supporting_source_lines` | `{path, start_line, end_line, snippet}` |
| `root_cause` | why the pattern is (or is not) a weakness |
| `explanation` | detector/knowledge-grounded narrative |
| `remediation` | what to change |

Also allowed: `unit_id`, `confidence` (0–1), `evidence_ids`. `additionalProperties` is false.

Internal model: `ReasoningResult` / `CWERef` / `SourceSpan` in `src/cwe_vuln/models/reasoning.py` (`to_dict` / `from_dict`). Schema helpers live in `src/cwe_vuln/schema/`. Agents must speak this contract, not ad-hoc dicts.

Shared knobs: `src/cwe_vuln/config.py` (`top_k`, `rrf_k`, LLM env var names). How packages compose: [`architecture.md`](architecture.md).

## Samples

Valid (must pass `uv run cwe-vuln-schema …`):

- `data/schema_samples/vulnerable.json` — CWE-89 concat SQL
- `data/schema_samples/not_vulnerable.json` — CWE-89 prepared statement
- `data/schema_samples/uncertain.json` — CWE-502 safe reader, decision uncertain

Invalid on purpose (tests only, not a model output):

- `data/schema_samples/invalid_missing_fields.json` — missing required fields

```bash
uv run pytest tests/schema/test_schema.py
uv run cwe-vuln-schema data/schema_samples/vulnerable.json data/schema_samples/not_vulnerable.json data/schema_samples/uncertain.json
# expected: VALID for those three; the invalid file is asserted in tests
```

## Later work (not Assignment 4 itself)

SAST evidence, template reasoner, validator, orchestrator, and `cwe-vuln-pipeline` landed in PRs #5–#9. MiniLM embeddings + Groq `LLMReasoner` (offline `TemplateReasoner` fallback) landed on `embeddings-llm`. Layout: [`architecture.md`](architecture.md).
