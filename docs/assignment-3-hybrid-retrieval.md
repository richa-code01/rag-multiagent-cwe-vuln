# Assignment 3: Hybrid retrieval

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

**seed-only — not a benchmark.** Numbers below were produced by `uv run cwe-vuln-retrieve` on 18 authored queries against the curated CWE store. They are not Juliet / OWASP Benchmark / Big-Vul results.

This assignment does **not** implement a reasoning agent.

## What “semantic” means here

No neural embedding model is installed (MiniLM / sentence-transformers was skipped to keep `uv sync` small and offline-friendly).

- **Lexical vector space:** TF-IDF cosine over CWE name + description + mitigations + detection notes (`src/cwe_vuln/retrieval.py`, stdlib only).
- **Second independent signal:** Assignment 1 SAST-style regex rules run on the linked Java unit source when `unit_id` is present (otherwise on the query text).
- **Third signal:** one-hop CWE relationship expansion from Assignment 2 (`parents` / `children` / `peers`).
- **Hybrid:** Reciprocal Rank Fusion (RRF, k=60) over the three rankings.

So this is **hybrid lexical + rule + graph**, not dense RAG. A later phase can swap TF-IDF for a local MiniLM encoder without changing the RRF combine.

## Corpus and queries

- Corpus: entries in `data/cwe/knowledge.json` (seed CWEs + related nodes).
- Labeled set: `data/retrieval/labeled_queries.jsonl` — 12 unit-note queries (one per Java seed unit; gold CWE = the unit’s `cwe_id`) plus 6 short natural-language descriptions (one per seed CWE). Queries do **not** include `CWE-xx` ids, so ranking is not a trivial id lookup.
- Java sources contain CWE ids in comments; those sources are used only for the SAST signal on unit-linked queries, not as TF-IDF documents.

## How to run

```bash
uv run pytest
uv run cwe-vuln-retrieve
uv run cwe-vuln-retrieve --query "string concatenated SQL command sent to a database statement"
uv run cwe-vuln-retrieve --query "password stored as a string literal" --unit-id java_cwe798_hardcoded
```

Writes `results/assignment-3-retrieval.json` and `results/assignment-3-retrieval.md`.

## Recorded seed metrics

From the checked-in run (18 queries):

| System | Recall@1 | Recall@3 | Recall@5 | MRR |
| --- | ---: | ---: | ---: | ---: |
| lexical_tfidf | 0.778 | 0.944 | 0.944 | 0.868 |
| sast | 0.333 | 0.333 | 0.333 | 0.333 |
| hybrid_rrf | 0.778 | 0.944 | 1.000 | 0.872 |

Interpretation on this seed (not a benchmark):

- SAST-only Recall@1 = 0.333 because only the six *vulnerable* unit queries contain regex-matching source; note/NL queries and safe units usually do not fire rules.
- Lexical TF-IDF already ranks the gold CWE at rank 1 for most note/NL queries.
- Hybrid RRF **does not change Recall@1** versus TF-IDF on this set, slightly improves **MRR** (0.868 → 0.872) and lifts **Recall@5** from 0.944 to **1.000** by pulling relationship neighbors into the tail.

If these numbers look strong, remember the corpus and queries were authored together. **seed-only — not a benchmark.**
