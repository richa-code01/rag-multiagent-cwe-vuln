# Framework seed results

**seed-only — not a benchmark.**

seed-only — not a benchmark. Metrics are the authored Java seed (test split default; pass --split all for all 12 units).

- Split: `test` (4 units)
- Embedder: `minilm`
- Offline ablation: `False`
- LLM configured: `True`
- Validation pass: 4/4
- SAST disagreement warnings: 0
- Paths: `{'sast_then_llm': 2, 'hybrid_retrieve_then_llm': 2}`
- Reasoners: `{'llm': 4}`

| Precision | Recall | F1 | TP | FP | TN | FN |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1.000 | 1.000 | 1.000 | 2 | 0 | 2 | 0 |
