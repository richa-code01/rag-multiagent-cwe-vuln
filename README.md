# RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases

**Student:** Richa Verma (25MCSS02)
**Advisor:** Dr. Akshay Pandey
**Current milestone:** layered seed pipeline (`cwe-vuln-pipeline`)

Canonical context: [`rag-multiagent-context.txt`](rag-multiagent-context.txt)
Sequence: [`docs/advisor-phase-plan.md`](docs/advisor-phase-plan.md) · Architecture: [`docs/architecture.md`](docs/architecture.md) · Plan: [`docs/implementation-plan.md`](docs/implementation-plan.md)

## Problem statement

This thesis studies **explainable** vulnerability detection: map a Java unit to a CWE and ground that mapping in a CWE knowledge base. The runnable path is a **seed-only** offline pipeline (regex SAST + lexical hybrid retrieval + template reasoner). It is **not** a public benchmark and does not call an LLM unless a key-backed implementation is added later.

## Pipeline

```text
Java SeedUnit
    → SAST Evidence[]              sast (detector + evidence)
    → hybrid RankedHit[]           TF-IDF + SAST + CWE relationships (RRF)
    → ReasoningResult              template reasoner (A4 JSON Schema)
    → ValidationReport             schema / KB / cited lines / decision
    → metrics vs seed labels
```

End-to-end:

```bash
uv sync
uv run pytest
uv run cwe-vuln-pipeline
```

Default split is the **4 test units**. `uv run cwe-vuln-pipeline --split all` runs all 12. Writes `results/framework-seed.json`.

Recorded test-split metrics (**seed-only — not a benchmark**): precision=1.000 recall=1.000 F1=1.000 FP=0 FN=0. Validator passed 4/4. Paths: 2× `sast_first_skip_llm`, 2× `hybrid_retrieve_skip_llm`.

## Honest status

| Piece | Status |
| --- | --- |
| Java seed (12 units, 6 CWEs, 8/4 split) | Done ([PR #1](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/1)) |
| Regex baseline + P/R/F1 | Done (A1) `uv run cwe-vuln` |
| CWE knowledge store + query API | Done ([PR #2](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/2)) `uv run cwe-vuln-kb demo` |
| Hybrid retrieval (TF-IDF + SAST + relationships) | Done ([PR #3](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/3)) `uv run cwe-vuln-retrieve` |
| Neural embeddings / dense RAG | **Not implemented** (TF-IDF is lexical) |
| Reasoning output JSON Schema | Done ([PR #4](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/4)) |
| SAST evidence objects | Done ([PR #5](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/5)) |
| Template reasoning agent | Done ([PR #6](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/6)) |
| Validator | Done ([PR #7](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/7)) |
| Cost-aware orchestrator | Done ([PR #8](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/8)) |
| Framework CLI on the seed | Done ([PR #9](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/9)) |
| Layered packages (`models`, `dataset`, `sast`, …) | **This PR** |
| Live LLM reasoner | **Not implemented** (skipped without a key) |

No Juliet / OWASP Benchmark / Big-Vul numbers.

## Seed (Assignment 1)

`data/seed/java/` + `data/seed/labels.jsonl`. Split lists in `src/cwe_vuln/dataset/seed.py`.

| Split | n | CWEs | Labels |
| --- | --- | --- | --- |
| train | 8 | 89, 79, 22, 502 (vuln+safe each) | 4 / 4 |
| test | 4 | 798, 327 (vuln+safe each) | 2 / 2 |

A1 regex-only overall (**seed-only**): P=1.000 R=1.000 F1=1.000 FP=0 FN=0.

## Knowledge / retrieval / schema

- Knowledge: `uv run cwe-vuln-kb demo` — [`docs/assignment-2-cwe-knowledge.md`](docs/assignment-2-cwe-knowledge.md)
- Retrieval (18 queries, **seed-only**): hybrid R@1=0.778 R@3=0.944 R@5=1.000 MRR=0.872 — [`docs/assignment-3-hybrid-retrieval.md`](docs/assignment-3-hybrid-retrieval.md)
- Schema: `uv run cwe-vuln-schema data/schema_samples/vulnerable.json` — [`docs/assignment-4-output-schema.md`](docs/assignment-4-output-schema.md)
- Evidence: `uv run cwe-vuln-evidence --unit-id java_cwe89_sqli_concat` — [`docs/sast-evidence.md`](docs/sast-evidence.md)

## Install

Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest
uv run cwe-vuln-pipeline
```
