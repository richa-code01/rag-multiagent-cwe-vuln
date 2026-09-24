# Chapter 8 — Error analysis

Generated from `results/thesis/llm_then_research_test.json` and `llm_then_juliet_pairs.json`. No live LLM. Do not treat this chapter as a new measurement.

## C2 pair failures by family

A pair is correct only if `bad → vulnerable` and `good → not_vulnerable`. `uncertain` is incorrect.

| CWE | n pairs | correct | multi-file variants | any uncertain |
| --- | ---: | ---: | ---: | ---: |
| CWE-23 | 3 | 2 | 0 | 1 |
| CWE-259 | 3 | 1 | 0 | 0 |
| CWE-327 | 3 | 1 | 0 | 1 |
| CWE-328 | 3 | 3 | 0 | 0 |
| CWE-80 | 3 | 2 | 0 | 0 |
| CWE-89 | 3 | 0 | 0 | 1 |

### Failed pairs

| CWE | pair_id (truncated) | bad | good | multi-file |
| --- | --- | --- | --- | --- |
| CWE-23 | juliet_CWE23_Relative_Path_Traversal_CWE23_Relative_Path_Traversal__File_41__pai | uncertain | vulnerable | no |
| CWE-259 | juliet_CWE259_Hard_Coded_Password_CWE259_Hard_Coded_Password__driverManager_42__ | not_vulnerable | not_vulnerable | no |
| CWE-259 | juliet_CWE259_Hard_Coded_Password_CWE259_Hard_Coded_Password__kerberosKey_45__pa | vulnerable | vulnerable | no |
| CWE-327 | juliet_CWE327_Use_Broken_Crypto_CWE327_Use_Broken_Crypto__3DES_08__pair0 | vulnerable | uncertain | no |
| CWE-327 | juliet_CWE327_Use_Broken_Crypto_CWE327_Use_Broken_Crypto__DES_03__pair0 | vulnerable | vulnerable | no |
| CWE-80 | juliet_s01_CWE80_XSS__CWE182_Servlet_connect_tcp_13__pair0 | vulnerable | vulnerable | no |
| CWE-89 | juliet_s01_CWE89_SQL_Injection__connect_tcp_prepareStatement_21__pair0 | uncertain | uncertain | no |
| CWE-89 | juliet_s01_CWE89_SQL_Injection__console_readLine_execute_01__pair0 | vulnerable | vulnerable | no |

### Incomplete pairs (TPD, not a model error)

| CWE | pair_id (truncated) | bad | good |
| --- | --- | --- | --- |
| CWE-89 | juliet_s04_CWE89_SQL_Injection__URLConnection_prepareStatement_14__pair0 | vulnerable | (missing) |

**Sampling bug (methodology, not a model result):** Juliet `_NNa/_NNb` flow variants hide the sink in a sibling file. Those IDs are excluded from later pair pools. The first C2 run that included them is archived under `results/thesis/archive/` when regenerated, not deleted.

## CWE-0 and unknown ids

- C1 predicted `CWE-0`: 0 / 24
- C2 predicted `CWE-0`: 0 / 35

Later runs clamp unknown ids (including `CWE-0`) to the top retrieved/evidence KB id and record `cwe_clamped_from`.

## `uncertain` (abstention)

- C1 uncertain units: 0 / 24
- C2 uncertain units: 4 / 35

Pair metric: any uncertain decision makes the pair incorrect. Binary `metrics` treat uncertain as `not_vulnerable` (abstain-as-negative). `metrics_exclude_abstain` drops those units.

## CWE match tiers on C2 (recomputed offline; peers are not family)

| tier | n |
| --- | --- |
| exact | 14 |
| none | 7 |
| parent_child | 14 |

Exact is the classification number. Family in later tables is exact or parent/child only.

## Cited lines (indent confound)

C1 cited_lines raw rate: 0.458. Indent-normalized: 0.917.
C2 cited_lines raw rate: 0.514. Indent-normalized: 0.857.

A large share of raw citation failures are whitespace/indent only (`snippet.strip() in excerpt` vs per-line strip). Spans are never rewritten.

## Comment-trap SAST confound

raw-disk SAST FP=12; sanitized SAST FP=6; template FP=6. Comment-only regex hits vanish after blanking and must not be credited to the reasoner.

## Retrieval query (file head vs sink window)

Archived contaminated-sample hybrid R@1: 0.1389.
Rebuilt single-file sample (`retrieval_query_text` evidence/sink window): hybrid R@1=0.25, MiniLM R@1=0.1667, SAST-channel R@1=0.1944.

This is retrieval recall of the gold CWE id, not detection F1. Do not claim RAG helps detection until `llm_no_retrieval_juliet_pairs` exists.

## What this does *not* prove

- RAG on Juliet is unproven until `llm_no_retrieval_juliet_pairs` exists.
- C1 F1 is trap-overfit by construction. C4 no-retrieval matching C1 F1 means retrieval did not change trap detection on this snapshot.
- C3 skipped/partial LLM rows are not a real-world claim.
- An incomplete C2 pair from TPD is not a model miss.
