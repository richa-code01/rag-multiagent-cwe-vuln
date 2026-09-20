# Chapter 5 — Results

Generated `2026-09-20T03:51:58Z`. Raw JSON: `results/thesis/`. Prompts sanitized. Lead with **CWE exact** and **pair accuracy + CI**. Family match is parent/child only; peers are a separate column.

## C1 Authored traps (n=24) — trap-overfit contrast, not the public headline

| System | Status | Precision | Recall | F1 | FP | FN | n |
| --- | --- | --- | --- | --- | --- | --- | --- |
| sast_regex_research_test | ok | 0.000 | 0.000 | 0.000 | 12 | 12 | 24 |
| sast_regex_sanitized_research_test | ok | 0.000 | 0.000 | 0.000 | 6 | 12 | 24 |
| template_research_test | ok | 0.000 | 0.000 | 0.000 | 6 | 12 | 24 |
| llm_then_research_test | ok | 0.857 | 1.000 | 0.923 | 2 | 0 | 24 |
| llm_no_retrieval_research_test | ok | 0.857 | 1.000 | 0.923 | 2 | 0 | 24 |
| llm_no_sast_research_test | ok | 0.923 | 1.000 | 0.960 | 1 | 0 | 24 |

- CWE exact: 17/24 (0.708)
- CWE parent/child (includes exact): 21/24 (0.875)
- CWE peer-only: 0/24 (0.000)
- CWE family (exact or parent/child, **not** peers): 21/24 (0.875)
- Validator pass: 11/24 (cited_lines raw 0.458; indent-normalized 0.917; no span rewrite)
- Abstain rate: 0.000
- Tokens: prompt 33352 + completion 20378 = 53730; mean latency 14383.4 ms
- Paths: `{'hybrid_retrieve_then_llm': 18, 'sast_then_llm': 6}`

Raw-disk regex SAST is 12 FP / 12 FN by trap construction. Template F1 on **sanitized** units is the fair regex contrast (comment-only hits are blanked). C1 F1 is that recovery, not Juliet.

C4 on C1 (same 24 units): no-retrieval F1 vs full LLM vs no-SAST is in the table above. Do not claim “RAG helps” unless no-retrieval is worse than the full path. Do not claim “SAST evidence helps” unless no-SAST is worse.

## C2 Juliet good/bad pairs (primary public LLM number)

| System | Status | Precision | Recall | F1 | FP | FN | n |
| --- | --- | --- | --- | --- | --- | --- | --- |
| sast_regex_juliet_pairs | ok | 0.615 | 0.444 | 0.516 | 5 | 10 | 36 |
| sast_regex_sanitized_juliet_pairs | ok | 0.615 | 0.444 | 0.516 | 5 | 10 | 36 |
| template_juliet_pairs | ok | 0.615 | 0.444 | 0.516 | 5 | 10 | 36 |
| llm_then_juliet_pairs | partial | 0.750 | 0.833 | 0.789 | 5 | 3 | 35 |
| llm_no_retrieval_juliet_pairs | skipped | — | — | — | — | — | — |

- C2 LLM status: `partial` (n_scored=35/36)
- **Pair accuracy (complete pairs only):** 9/17 = 0.529
- Incomplete pairs excluded (TPD abort, not a model error): 1
- Bootstrap 95% CI (percentile, n_boot=1000): [0.2941, 0.7647], mean 0.5294
- Pair abstain (any `uncertain` on a complete pair): 3 / 17 (0.176)
- CWE exact: 14/35 (0.400)
- CWE parent/child (includes exact): 28/35 (0.800)
- CWE peer-only: 0/35 (0.000)
- CWE family (exact or parent/child, **not** peers): 28/35 (0.800)
- Validator pass: 18/35
- Abstain rate (units): 0.114
- Tokens: 96540 total; mean latency 2385.5 ms
- CWE-502: not present in Juliet Java 1.3
- Multi-file Juliet variants: excluded from the pair pool; the first C2 run that included `_NNa` files is archived under `results/thesis/archive/` if present.

Per-family FPR (binary, abstain-as-negative) on scored C2 units:

| CWE | FP | TN | FPR |
| --- | --- | --- | --- |
| CWE-23 | 1 | 2 | 0.333 |
| CWE-259 | 1 | 2 | 0.333 |
| CWE-327 | 1 | 2 | 0.333 |
| CWE-328 | 0 | 3 | 0.000 |
| CWE-80 | 1 | 2 | 0.333 |
| CWE-89 | 1 | 1 | 0.500 |

Families sampled: CWE-89, 80, 23, 327, 328, 259 (nearby ids kept, not relabeled to 79/22/798). Complete-pair n is smaller than 18 if TPD aborted a unit; report the CI, do not over-precision.

## C3 Sliced Vul4J

Regex SAST on the planned sliced units is kept if present. Live LLM is **skipped** (n_scored=None). **Do not cite a partial LLM F1 as a real-world result.**

## C4 / C5 / C7 / C8

- C4 LLM no-retrieval / no-SAST **ran**.
- C5 Semgrep: see `semgrep_juliet_pairs.json` (skipped if not installed). Not compared to CodeQL (not run).
- C7 model ablation skipped unless `--include-model-ablation` and TPD remain.
- C8 `results/thesis/human_spotcheck.json` status `not_run` — unit ids may be sampled; labels are empty until Richa.

## Six-suite regex SAST (kept; not this LLM run)

From `results/benchmarks/summary.json` (`llm_rows_retracted=true`): Juliet n=20728 F1=0.316; OWASP n=2740 F1=0.395; Securibench n=119 F1=0.072; find-sec-bugs n=79 F1=0.435; Vul4J n=62 F1=0.244; CVEfixes-Java-slice n=92 F1=0.207. Regex ≠ CodeQL.
