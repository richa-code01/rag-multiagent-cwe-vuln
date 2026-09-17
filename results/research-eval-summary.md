# Research evaluation summary

**authored corpus — not a public benchmark.**

authored corpus — not a public benchmark. Metrics are computed only on the authored Java units and labeled queries in this repository. Not Juliet, OWASP Benchmark, or Big-Vul.

- Generated: `2026-09-17T03:59:03Z`
- Seed n=12 (8/4 assignment split) · research test n=24 · corpus n=36

## Detection (research trials)

| System | Precision | Recall | F1 | FP | FN | n | Validator |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| sast_regex_research_test | 0.000 | 0.000 | 0.000 | 12 | 12 | 24 | — |
| template_skip_llm_research_test | 0.000 | 0.000 | 0.000 | 12 | 12 | 24 | 24/24 |
| llm_then_research_test | 0.857 | 1.000 | 0.923 | 2 | 0 | 24 | 24/24 |
| llm_then_seed_test | 1.000 | 1.000 | 1.000 | 0 | 0 | 4 | 4/4 |
| llm_skip_when_sast_research_test | 0.500 | 1.000 | 0.667 | 12 | 0 | 24 | 12/24 |

## Retrieval (expanded authored queries)

| System | R@1 | R@3 | R@5 | R@10 | MRR |
| --- | ---: | ---: | ---: | ---: | ---: |
| retrieval_hybrid_rrf_expanded | 0.854 | 0.958 | 1.000 | 1.000 | 0.917 |
| retrieval_minilm_expanded | 0.812 | 0.979 | 1.000 | 1.000 | 0.894 |
| retrieval_tfidf_expanded | 0.646 | 0.917 | 0.938 | 1.000 | 0.794 |

## Trial log

- `sast_regex_research_test` status=ok
- `template_skip_llm_research_test` status=ok
- `retrieval_tfidf_expanded` status=ok
- `retrieval_minilm_expanded` status=ok
- `retrieval_hybrid_rrf_expanded` status=ok
- `retrieval_expanded_all_systems` status=ok
- `llm_then_research_test` status=ok
- `llm_then_seed_test` status=ok
- `llm_skip_when_sast_research_test` status=ok
- `llm_skip_when_sast_research_test_label_leak` status=invalid_label_leak
- `llm_then_research_test_label_leak` status=invalid_label_leak
- `sast_fn_traps_javadoc_false_start` status=failed error=FN traps matched regex via documentation text, not executable code
- `sast_fp_traps_javadoc_rewrite_regression` status=failed error=fp_count dropped from 12 to 10 after javadoc neutralization
