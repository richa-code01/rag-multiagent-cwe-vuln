# Assignment 3: Hybrid retrieval

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

**seed-only — not a benchmark.** Numbers below were produced by `uv run cwe-vuln-retrieve --eval` on 18 authored queries against the curated CWE store. They are not Juliet / OWASP Benchmark / Big-Vul results.

This assignment does **not** implement a reasoning agent.

## What “semantic” means here

Dense embeddings are a real MiniLM path, with TF-IDF as the lexical baseline and the download fallback.

- **Neural vector space:** `MiniLMEmbedder` (`sentence-transformers` / `all-MiniLM-L6-v2`) cosine over CWE name + description + mitigations + detection notes. Model files cache under `.cache/sentence-transformers/` (gitignored). First CLI run may download; if that fails, `embedder=tfidf_fallback`.
- **Lexical vector space:** `TfidfIndex` / `TfidfEmbedder` TF-IDF cosine (stdlib + the same documents).
- **Second independent signal:** Assignment 1 SAST-style regex rules run on the linked Java unit source when `unit_id` is present (otherwise on the query text).
- **Third signal:** one-hop CWE relationship expansion from Assignment 2 (`parents` / `children` / `peers`).
- **Hybrid:** Reciprocal Rank Fusion (RRF, k=60) over **neural + SAST + relationships**.

Unit tests use a tiny fake embedder and never require MiniLM. Optional integration test is skipped when the model is not cached.

## Corpus and queries

- Corpus: entries in `data/cwe/knowledge.json` (seed CWEs + related nodes).
- Labeled set: `data/retrieval/labeled_queries.jsonl` — 12 unit-note queries (one per Java seed unit; gold CWE = the unit’s `cwe_id`) plus 6 short natural-language descriptions (one per seed CWE). Queries do **not** include `CWE-xx` ids, so ranking is not a trivial id lookup.
- Java sources contain CWE ids in comments; those sources are used only for the SAST signal on unit-linked queries, not as embedding documents.

## How to run

```bash
uv run pytest
uv run cwe-vuln-retrieve --eval
uv run cwe-vuln-retrieve --query "string concatenated SQL command sent to a database statement"
uv run cwe-vuln-retrieve --query "password stored as a string literal" --unit-id java_cwe798_hardcoded
```

Writes `results/assignment-3-retrieval.json` and `results/assignment-3-retrieval.md`. The JSON `embedder` field is `minilm` or `tfidf_fallback`.

## Recorded seed metrics

From the checked-in run (18 queries, **embedder=`minilm`**):

| System | Recall@1 | Recall@3 | Recall@5 | MRR |
| --- | ---: | ---: | ---: | ---: |
| lexical_tfidf | 0.778 | 0.944 | 0.944 | 0.868 |
| neural | 0.944 | 1.000 | 1.000 | 0.972 |
| sast | 0.333 | 0.333 | 0.333 | 0.333 |
| hybrid_rrf | 0.944 | 1.000 | 1.000 | 0.972 |

Interpretation on this seed (not a benchmark):

- SAST-only Recall@1 = 0.333 because only the six *vulnerable* unit queries contain regex-matching source; note/NL queries and safe units usually do not fire rules.
- MiniLM cosine lifts Recall@1 vs lexical TF-IDF on this authored set (0.778 → 0.944) and reaches Recall@3/5 = 1.0.
- Hybrid RRF (neural + SAST + relationships) matches neural on this seed; SAST still matters as an independent signal for unit-linked queries.

If these numbers look strong, remember the corpus and queries were authored together. **seed-only — not a benchmark.**
