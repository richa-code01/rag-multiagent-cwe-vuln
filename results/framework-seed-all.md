# Framework seed results

**seed-only — not a benchmark.**

seed-only — not a benchmark. Metrics are the authored Java seed (test split default; pass --split all for all 12 units).

- Split: `all` (12 units)
- Embedder: `minilm`
- LLM configured: `True`
- Validation pass: 12/12
- Paths: `{'sast_then_llm': 6, 'hybrid_retrieve_then_llm': 6}`
- Reasoners: `{'llm': 12}`

| Precision | Recall | F1 | TP | FP | TN | FN |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1.000 | 1.000 | 1.000 | 6 | 0 | 6 | 0 |
