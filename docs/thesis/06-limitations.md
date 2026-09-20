# Chapter 6 — Limitations

- Groq free-tier **200k tokens/day** can stop C3/C4/C7. Partial rows are labeled `partial` / `not_run`, never filled in.
- Authored traps were written against our regexes; C1 F1 is that contrast, not Juliet.
- Juliet pair CI is wide on n=18. Multi-file `_NNa` variants are excluded because they hide the sink; that is a methodology choice, not a claim that the model handles inter-file flows.
- Regex SAST is not AST/taint/CodeQL/Semgrep. Fair contrast uses sanitized units.
- Knowledge store is a MITRE **subset**. Nearby Juliet gold (80 vs 79, 23 vs 22) is disclosed, not relabeled.
- `final_confidence` is uncalibrated and does not route.
- Cited-line pass is reported raw **and** indent-normalized; we do not rewrite spans.
- Single-rater C8 not run; no inter-rater statistics.
- No HTTP API, auth, or multi-tenant service (see HLD gaps).
- RAG benefit on Juliet is unproven until C4 `llm_no_retrieval_juliet_pairs` exists.
