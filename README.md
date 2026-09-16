# RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases

**Student:** Richa Verma (25MCSS02)
**Advisor:** Dr. Akshay Pandey
**Current milestone:** Assignment 2 — curated CWE knowledge layer (Assignment 1 seed + baseline is already on `main`)

Canonical session context: [`rag-multiagent-context.txt`](rag-multiagent-context.txt) (keep this file in sync with README and `docs/`).

## Problem statement

Software vulnerability detectors that only emit a yes/no flag are hard to trust in review. This thesis studies **explainable** detection: given a code unit, identify whether it is vulnerable, map it to a **CWE** (Common Weakness Enumeration) weakness, and (in later assignments) ground that explanation in a CWE knowledge base via retrieval.

This repository **does not yet implement** the full multi-agent framework. Implemented so far: an authored **Java seed** (12 units, 6 CWEs, explicit 8/4 train/test split), a **regex / SAST-style baseline** (no API key), and a **curated CWE knowledge store** with a query API. Detection scores are **seed-only — not a benchmark**.

## Eventual framework (not implemented here)

High-level pipeline. Only the seed, regex baseline, and CWE knowledge *store/query* exist in this PR.

```text
code unit
    → regex / SAST-style baseline (Assignment 1)
    → CWE knowledge lookup (Assignment 2)
    → (future) hybrid retrieval over the CWE knowledge layer
    → (future) SAST evidence extraction
    → (future) reasoning agent (structured explanation)
    → (future) validator agent
    → (future) cost-aware orchestrator
    → explainable finding (CWE + evidence + natural-language rationale)
```

Advisor sequence:

1. **Dataset + baseline** — done (PR #1)
2. **CWE knowledge layer** — this PR
3. Hybrid retrieval — not started
4. Structured reasoning output schema — not started

After those four: SAST evidence extraction, reasoning agent, validator, cost-aware orchestrator, then the full framework. See [`docs/advisor-phase-plan.md`](docs/advisor-phase-plan.md).

## Honest status

| Piece | Status |
| --- | --- |
| Authored Java seed (6 CWEs, 12 units, 8/4 split) | Done (Assignment 1) |
| Regex / SAST-style baseline + precision/recall/F1 | Done (Assignment 1) |
| CWE knowledge store + query interface (Assignment 2) | **This PR** |
| Hybrid retrieval / RAG (Assignment 3) | **Not implemented** |
| Structured reasoning schema (Assignment 4) | **Not implemented** |
| Multi-agent orchestration, SAST evidence product pipeline, cost-aware routing | **Not implemented** |

There are **no public-benchmark numbers** in this repo (no Juliet / OWASP Benchmark / Big-Vul results) and **no claim that evaluation of the thesis system is done**.

## Seed dataset (Assignment 1)

Twelve small Java teaching units under `data/seed/java/`, labels in `data/seed/labels.jsonl`.

| Split | Units | CWEs (this split) | Labels |
| --- | --- | --- | --- |
| train | 8 | CWE-89, CWE-79, CWE-22, CWE-502 (vulnerable + not_vulnerable each) | 4 vuln / 4 safe |
| test | 4 | CWE-798, CWE-327 (vulnerable + not_vulnerable each) | 2 vuln / 2 safe |

The split is **deterministic**: explicit `unit_id` lists in `src/cwe_vuln/dataset.py`, mirrored by the `split` field on each label. Details: [`docs/assignment-1-dataset-baseline.md`](docs/assignment-1-dataset-baseline.md).

These are pedagogical detector samples, not exploit PoCs.

## Baseline

A regex detector (`src/cwe_vuln/detector.py`) looks for SAST-style patterns:

- CWE-89: SQL keyword string concatenated with `+`
- CWE-79: HTML markup concatenated without `htmlEncode(...)`
- CWE-22: `new File(...)` with string concatenation
- CWE-502: `ObjectInputStream` / `readObject`
- CWE-798: `password` / `apiKey` / `secret` assigned a string literal
- CWE-327: `getInstance("MD5"|"DES"|...)`

An optional LLM detector stub is **skipped** unless/until later assignments implement it (no key required for Assignment 1).

If recorded scores are perfect, that is because the seed is tiny and the rules were written against it. They are **seed-only — not a benchmark**.

## Install and reproduce

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest
uv run python -m cwe_vuln
# equivalent:
uv run cwe-vuln
uv run cwe-vuln-kb demo
uv run cwe-vuln-kb get CWE-89
uv run cwe-vuln-kb relationships CWE-798
uv run cwe-vuln-kb mitigations CWE-22
```

The eval writes:

- `results/assignment-1-baseline.json`
- `results/assignment-1-baseline.md`

Recorded metrics (re-run the command above to regenerate) are also copied into [`docs/assignment-1-dataset-baseline.md`](docs/assignment-1-dataset-baseline.md).

## Layout

```text
src/cwe_vuln/     Python package (dataset, detector, knowledge, metrics, eval)
data/seed/        labels.jsonl + java/ teaching units
data/cwe/         curated CWE JSON knowledge store
tests/            split + metrics + detector + knowledge plumbing
docs/             advisor plan + assignment write-ups
results/          generated baseline metrics
```

CWE knowledge details: [`docs/assignment-2-cwe-knowledge.md`](docs/assignment-2-cwe-knowledge.md).
Advisor sequence: [`docs/advisor-phase-plan.md`](docs/advisor-phase-plan.md).
