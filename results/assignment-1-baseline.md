# Assignment 1 baseline results

**seed-only — not a benchmark.**

seed-only — not a benchmark. Metrics are computed only on this 12-unit authored pedagogical seed. Rules were written against the same seed. Do not treat these scores as Juliet, OWASP Benchmark, or Big-Vul results.

- Generated at: `2026-09-16T18:26:40Z`
- Detector: `regex_sast_style`
- LLM detector: `skipped_no_api_key`
- Units: 12 (train 8 / test 4)

## Binary metrics (vulnerable vs not_vulnerable)

| Split | Precision | Recall | F1 | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| overall | 1.000 | 1.000 | 1.000 | 6 | 0 | 6 | 0 |
| train | 1.000 | 1.000 | 1.000 | 4 | 0 | 4 | 0 |
| test | 1.000 | 1.000 | 1.000 | 2 | 0 | 2 | 0 |

## Per-CWE (seed subsets only)

| CWE | Precision | Recall | F1 | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-89 | 1.000 | 1.000 | 1.000 | 1 | 0 | 1 | 0 |
| CWE-79 | 1.000 | 1.000 | 1.000 | 1 | 0 | 1 | 0 |
| CWE-22 | 1.000 | 1.000 | 1.000 | 1 | 0 | 1 | 0 |
| CWE-502 | 1.000 | 1.000 | 1.000 | 1 | 0 | 1 | 0 |
| CWE-798 | 1.000 | 1.000 | 1.000 | 1 | 0 | 1 | 0 |
| CWE-327 | 1.000 | 1.000 | 1.000 | 1 | 0 | 1 | 0 |

## Predictions

- `java_cwe89_sqli_concat` [train] gold=vulnerable pred=vulnerable rules=['sql_string_concat'] (ok)
- `java_cwe89_sqli_prepared` [train] gold=not_vulnerable pred=not_vulnerable rules=— (ok)
- `java_cwe79_xss_unescaped` [train] gold=vulnerable pred=vulnerable rules=['html_output_unencoded'] (ok)
- `java_cwe79_xss_encoded` [train] gold=not_vulnerable pred=not_vulnerable rules=— (ok)
- `java_cwe22_path_concat` [train] gold=vulnerable pred=vulnerable rules=['file_path_concat'] (ok)
- `java_cwe22_path_resolved` [train] gold=not_vulnerable pred=not_vulnerable rules=— (ok)
- `java_cwe502_readobject` [train] gold=vulnerable pred=vulnerable rules=['java_deserialization'] (ok)
- `java_cwe502_json_parse` [train] gold=not_vulnerable pred=not_vulnerable rules=— (ok)
- `java_cwe798_hardcoded` [test] gold=vulnerable pred=vulnerable rules=['hardcoded_secret_literal'] (ok)
- `java_cwe798_env_config` [test] gold=not_vulnerable pred=not_vulnerable rules=— (ok)
- `java_cwe327_md5` [test] gold=vulnerable pred=vulnerable rules=['weak_crypto_algorithm'] (ok)
- `java_cwe327_sha256` [test] gold=not_vulnerable pred=not_vulnerable rules=— (ok)
