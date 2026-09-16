# Assignment 3 hybrid retrieval results

**seed-only — not a benchmark.**

seed-only — not a benchmark. Queries are the 12 unit notes plus 6 short descriptions. TF-IDF is lexical (not neural embeddings). Hybrid is RRF of TF-IDF + SAST-style rules + CWE relationship expansion.

- Queries: 18

## Macro metrics

| System | Recall@1 | Recall@3 | Recall@5 | MRR |
| --- | ---: | ---: | ---: | ---: |
| lexical_tfidf | 0.778 | 0.944 | 0.944 | 0.868 |
| sast | 0.333 | 0.333 | 0.333 | 0.333 |
| hybrid_rrf | 0.778 | 0.944 | 1.000 | 0.872 |
