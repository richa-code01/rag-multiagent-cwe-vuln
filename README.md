# RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases

**Student:** Richa Verma (25MCSS02)
**Advisor:** Dr. Akshay Pandey
**Current milestone:** Assignment 3 — hybrid CWE retrieval (Assignments 1–2 are on `main`)

Canonical session context: [`rag-multiagent-context.txt`](rag-multiagent-context.txt) (keep this file in sync with README and `docs/`).

## Problem statement

Software vulnerability detectors that only emit a yes/no flag are hard to trust in review. This thesis studies **explainable** detection: given a code unit, identify whether it is vulnerable, map it to a **CWE** (Common Weakness Enumeration) weakness, and ground that mapping in a CWE knowledge base via retrieval.

This repository **does not yet implement** the full multi-agent framework. Implemented: authored Java seed, regex/SAST-style baseline, curated CWE knowledge queries, and hybrid retrieval (lexical TF-IDF + SAST rules + CWE relationships). Scores are **seed-only — not a benchmark**.

## Pipeline sketch

```text
code unit
    → regex / SAST-style baseline (Assignment 1)
    → CWE knowledge lookup (Assignment 2)
    → hybrid retrieval over the CWE store (Assignment 3; lexical TF-IDF, not neural RAG)
    → (future) SAST evidence extraction
    → (future) reasoning agent (structured explanation)
    → (future) validator agent
    → (future) cost-aware orchestrator
    → explainable finding (CWE + evidence + natural-language rationale)
```

Advisor sequence: [`docs/advisor-phase-plan.md`](docs/advisor-phase-plan.md).

1. Dataset + baseline — done ([PR #1](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/1))
2. CWE knowledge layer — done ([PR #2](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/2))
3. Hybrid retrieval — **this PR**
4. Structured reasoning output schema — not started

## Honest status

| Piece | Status |
| --- | --- |
| Authored Java seed (6 CWEs, 12 units, 8/4 split) | Done (Assignment 1) |
| Regex / SAST-style baseline + precision/recall/F1 | Done (Assignment 1) |
| CWE knowledge store + query interface | Done (Assignment 2) |
| Hybrid retrieval (TF-IDF + SAST + relationships, RRF) | **This PR** (Assignment 3) |
| Neural embeddings / full RAG | **Not implemented** (A3 is lexical TF-IDF) |
| Structured reasoning schema (Assignment 4) | **Not implemented** |
| SAST evidence objects, reasoning agent, validator, cost-aware orchestrator, full framework | **Not implemented** |

No Juliet / OWASP Benchmark / Big-Vul numbers. Thesis-system evaluation is **not** done.

## Seed dataset (Assignment 1)

Twelve Java teaching units: `data/seed/java/` + `data/seed/labels.jsonl`. Deterministic 8/4 split in `src/cwe_vuln/dataset.py`.

| Split | Units | CWEs | Labels |
| --- | --- | --- | --- |
| train | 8 | CWE-89, CWE-79, CWE-22, CWE-502 (vuln+safe each) | 4 vuln / 4 safe |
| test | 4 | CWE-798, CWE-327 (vuln+safe each) | 2 vuln / 2 safe |

Details: [`docs/assignment-1-dataset-baseline.md`](docs/assignment-1-dataset-baseline.md). Pedagogical samples, not exploit PoCs.

Recorded detection metrics (**seed-only — not a benchmark**): overall P=1.000 R=1.000 F1=1.000 FP=0 FN=0. Reproduce: `uv run cwe-vuln`.

## CWE knowledge (Assignment 2)

`data/cwe/knowledge.json` + `CWEKnowledgeBase`. Run `uv run cwe-vuln-kb demo`. Doc: [`docs/assignment-2-cwe-knowledge.md`](docs/assignment-2-cwe-knowledge.md).

## Hybrid retrieval (Assignment 3)

Lexical TF-IDF cosine + SAST rule hits + one-hop CWE relationships, fused with RRF. **Not** MiniLM/sentence-transformers.

```bash
uv run cwe-vuln-retrieve
uv run cwe-vuln-retrieve --query "string concatenated SQL command sent to a database statement"
```

Recorded on 18 authored queries (**seed-only — not a benchmark**):

| System | Recall@1 | Recall@3 | Recall@5 | MRR |
| --- | ---: | ---: | ---: | ---: |
| lexical_tfidf | 0.778 | 0.944 | 0.944 | 0.868 |
| sast | 0.333 | 0.333 | 0.333 | 0.333 |
| hybrid_rrf | 0.778 | 0.944 | 1.000 | 0.872 |

Doc: [`docs/assignment-3-hybrid-retrieval.md`](docs/assignment-3-hybrid-retrieval.md). Results: `results/assignment-3-retrieval.json`.

## Install and reproduce

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest
uv run cwe-vuln
uv run cwe-vuln-kb demo
uv run cwe-vuln-retrieve
```

## Layout

```text
src/cwe_vuln/          dataset, detector, knowledge, retrieval, metrics, eval
data/seed/             labels.jsonl + java/ teaching units
data/cwe/              curated CWE JSON store
data/retrieval/        labeled retrieval queries
docs/                  advisor plan + assignment write-ups
results/               recorded seed metrics
rag-multiagent-context.txt
```
