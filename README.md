# RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases

**Student:** Richa Verma (25MCSS02)
**Advisor:** Dr. Akshay Pandey
**Current milestone:** Assignment 4 — structured reasoning output schema (Assignments 1–3 are on `main`)

Canonical context: [`rag-multiagent-context.txt`](rag-multiagent-context.txt)

## Problem statement

This thesis studies **explainable** vulnerability detection: map a code unit to a CWE and ground that mapping in a CWE knowledge base. The full multi-agent framework is **not** implemented yet.

Implemented: Java seed, regex/SAST baseline, curated CWE knowledge, hybrid retrieval (lexical TF-IDF + SAST + relationships), and a Draft 2020-12 JSON Schema for future reasoning output. Scores are **seed-only — not a benchmark**.

## Pipeline sketch

```text
code unit
    → regex / SAST-style baseline (A1)
    → CWE knowledge lookup (A2)
    → hybrid retrieval (A3; lexical TF-IDF, not neural RAG)
    → structured JSON (A4 schema; agent not built yet)
    → (future) SAST evidence extraction
    → (future) reasoning agent
    → (future) validator
    → (future) cost-aware orchestrator
```

See [`docs/advisor-phase-plan.md`](docs/advisor-phase-plan.md) (sequence) and [`docs/architecture.md`](docs/architecture.md) (how packages compose).

## Honest status

| Piece | Status |
| --- | --- |
| Java seed (12 units, 6 CWEs, 8/4 split) | Done (A1, [PR #1](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/1)) |
| Regex baseline + P/R/F1 | Done (A1) |
| CWE knowledge store + query API | Done (A2, [PR #2](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/2)) |
| Hybrid retrieval (TF-IDF + SAST + relationships) | Done (A3, [PR #3](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/3)) |
| Neural embeddings / full RAG | **Not implemented** |
| Reasoning output JSON Schema | **This PR** (A4) |
| Reasoning agent, SAST evidence objects, validator, orchestrator, framework | **Not implemented** |

No Juliet / OWASP Benchmark / Big-Vul numbers.

## Seed (Assignment 1)

`data/seed/java/` + `data/seed/labels.jsonl`. Split lists in `src/cwe_vuln/dataset.py`.

| Split | n | CWEs | Labels |
| --- | --- | --- | --- |
| train | 8 | 89, 79, 22, 502 (vuln+safe each) | 4 / 4 |
| test | 4 | 798, 327 (vuln+safe each) | 2 / 2 |

Detection on 12 units (**seed-only**): P=1.000 R=1.000 F1=1.000 FP=0 FN=0. `uv run cwe-vuln`

## Knowledge (Assignment 2)

`uv run cwe-vuln-kb demo` — [`docs/assignment-2-cwe-knowledge.md`](docs/assignment-2-cwe-knowledge.md)

## Retrieval (Assignment 3)

Lexical TF-IDF + SAST + relationship RRF. **Not** MiniLM.

| System | Recall@1 | Recall@3 | Recall@5 | MRR |
| --- | ---: | ---: | ---: | ---: |
| lexical_tfidf | 0.778 | 0.944 | 0.944 | 0.868 |
| sast | 0.333 | 0.333 | 0.333 | 0.333 |
| hybrid_rrf | 0.778 | 0.944 | 1.000 | 0.872 |

**seed-only.** `uv run cwe-vuln-retrieve` — [`docs/assignment-3-hybrid-retrieval.md`](docs/assignment-3-hybrid-retrieval.md)

## Output schema (Assignment 4)

`schemas/reasoning_output.schema.json` (Draft 2020-12) plus `ReasoningResult` dataclasses. Samples: `data/schema_samples/`. Docs: [`docs/assignment-4-output-schema.md`](docs/assignment-4-output-schema.md), [`docs/architecture.md`](docs/architecture.md)

```bash
uv run cwe-vuln-schema data/schema_samples/vulnerable.json data/schema_samples/not_vulnerable.json data/schema_samples/uncertain.json
```

## Install

Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest
uv run cwe-vuln
uv run cwe-vuln-kb demo
uv run cwe-vuln-retrieve
uv run cwe-vuln-schema data/schema_samples/vulnerable.json
```
