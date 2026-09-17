# Juliet Java benchmark results (measured)

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02)

**These numbers were computed by `cwe-vuln-eval` on this machine. They are not invented. They are not the authored 36-unit research table.**

Protocol: [`docs/benchmark-plan.md`](benchmark-plan.md). Authored-corpus table: [`docs/research-evaluation.md`](research-evaluation.md).

## Suite version and download

| Field | Recorded value |
| --- | --- |
| Suite | NIST Juliet Test Suite for Java **v1.3** (SARD 111) |
| Catalog | https://samate.nist.gov/SARD/test-suites/111 |
| NIST zip URL attempted | `https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip` |
| NIST zip result | **HTTP 403 Forbidden** (2026-09-17). Next: GitHub sparse clone. |
| Mirror that succeeded | `https://github.com/find-sec-bugs/juliet-test-suite.git` |
| Commit | `b2c6df3733e2176fe7097e4784895c6891632b4c` |
| Download date (UTC) | 2026-09-17T13:21:18Z |
| Method | `github_sparse_clone` of mapped `src/testcases/CWE*` folders |
| OWASP Benchmark | **Not run** (Juliet ingest of mapped/nearby families succeeded) |
| Retrieval@Juliet | **Skipped** (nearby gold ids 80/23/259/328/… are not in the curated six-CWE store) |

Provenance file: `data/benchmarks/juliet_provenance.json`. Java tree is gitignored under `data/benchmarks/juliet-java/`.

## CWE mapping (no silent relabel)

| Thesis CWE | Juliet Java 1.3 | Ingested gold id | n units (good / bad) |
| --- | --- | --- | ---: |
| CWE-89 | `CWE89_SQL_Injection` | CWE-89 | 11835 (9555 / 2280) |
| CWE-79 | **no folder** | nearby CWE-80, CWE-81, CWE-83 | 2664 / 1332 / 1332 |
| CWE-22 | **no folder** | nearby CWE-23, CWE-36 | 1443 / 1443 |
| CWE-502 | **no folder** | — | 0 |
| CWE-798 | **no folder** | nearby CWE-259, CWE-321 | 333 / 111 |
| CWE-327 | `CWE327_Use_Broken_Crypto` | CWE-327 | 94 (60 / 34) |
| (nearby hash) | `CWE328_Reversible_One_Way_Hash` | CWE-328 (not relabeled to 327) | 141 (90 / 51) |

**Ingested units: 20,728** (method-level or filename-level good/bad). Not the full 28,881-case suite: only mapped/nearby folders above. More good than bad because mixed files often emit several `good*` methods per `bad()`.

## 1) Full regex SAST

**Juliet Java v1.3, CWE subset {89,80,81,83,23,36,327,328,259,321}, n=20728, SAST on all ingested units.**

| System | Precision | Recall | F1 | TP | FP | TN | FN | n |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Regex SAST | 0.300 | 0.334 | 0.316 | 1604 | 3736 | 12195 | 3193 | 20728 |

Per Juliet gold CWE:

| CWE | P | R | F1 | TP | FP | TN | FN | n |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-89 | 0.292 | 0.553 | 0.382 | 1260 | 3060 | 6495 | 1020 | 11835 |
| CWE-80 | 0.000 | 0.000 | 0.000 | 0 | 18 | 1962 | 684 | 2664 |
| CWE-81 | 0.000 | 0.000 | 0.000 | 0 | 9 | 981 | 342 | 1332 |
| CWE-83 | 0.000 | 0.000 | 0.000 | 0 | 9 | 981 | 342 | 1332 |
| CWE-23 | 0.307 | 0.605 | 0.407 | 276 | 624 | 363 | 180 | 1443 |
| CWE-36 | 0.000 | 0.000 | 0.000 | 0 | 12 | 975 | 456 | 1443 |
| CWE-327 | 1.000 | 1.000 | 1.000 | 34 | 0 | 60 | 0 | 94 |
| CWE-328 | 1.000 | 0.667 | 0.800 | 34 | 0 | 90 | 17 | 141 |
| CWE-259 | 0.000 | 0.000 | 0.000 | 0 | 3 | 216 | 114 | 333 |
| CWE-321 | 0.000 | 0.000 | 0.000 | 0 | 1 | 72 | 38 | 111 |

Raw: `results/benchmarks/sast_regex_juliet.json`. Seed-oriented regexes fire on some SQL/path/crypto patterns and miss XSS / hardcoded-password / absolute-path Juliet style. That is a measured limitation, not a paper claim of SOTA.

## 2) Stratified Groq sample

**Juliet Java v1.3, LLM on stratified sample Z: seed=13, 12 units × 6 CWE ids (6 bad / 6 good each), n=72.** Protocol target was 20/CWE; this run used **12** to stay on Groq free-tier (six families × 12 = 72 calls plus a template pass). **No HTTP 429** on the recorded run.

LLM families (SAST-only leftover ids 81, 83, 36, 321): **CWE-89, CWE-80, CWE-23, CWE-327, CWE-328, CWE-259**.

Manifest (committed): `data/benchmarks/juliet_llm_sample.json`.

Model: `openai/gpt-oss-20b` (`probe_ok`). Elapsed wall time ~694 s for template + live LLM.

### TemplateReasoner (same sample) — ablation

| System | Precision | Recall | F1 | TP | FP | TN | FN | n | Validator |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Template / skip-LLM | 0.727 | 0.444 | 0.552 | 16 | 6 | 30 | 20 | 72 | 72/72 |

Paths: `hybrid_retrieve_skip_llm=50`, `sast_first_skip_llm=22`. Reasoner `template=72`. Rate limited: no.

### Live Groq LLMReasoner (same sample) — system of record on this sample

| System | Precision | Recall | F1 | TP | FP | TN | FN | n | Validator |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Live Groq then_llm | 0.917 | 0.611 | 0.733 | 22 | 2 | 34 | 14 | 72 | 72/72 |

Reasoners: `llm=30`, `llm_fallback_template=42` (invalid JSON after retry → template fallback). Paths: `hybrid_retrieve_then_llm=50`, `sast_then_llm=22`. Rate limited: **no**. `skipped_due_to_rate_limit=0`.

Per-CWE on the **n=12 per id** sample:

| CWE | Template F1 | LLM F1 | LLM P | LLM R | LLM TP/FP/FN |
| --- | ---: | ---: | ---: | ---: | ---: |
| CWE-89 | 0.444 | 0.444 | 0.667 | 0.333 | 2 / 1 / 4 |
| CWE-80 | 0.000 | 0.000 | 0.000 | 0.000 | 0 / 0 / 6 |
| CWE-23 | 0.625 | 0.909 | 1.000 | 0.833 | 5 / 0 / 1 |
| CWE-327 | 1.000 | 1.000 | 1.000 | 1.000 | 6 / 0 / 0 |
| CWE-328 | 0.667 | 0.667 | 1.000 | 0.500 | 3 / 0 / 3 |
| CWE-259 | 0.000 | 0.923 | 0.857 | 1.000 | 6 / 1 / 0 |

CWE-80 XSS stays F1=0 (regex does not match Juliet XSS; LLM did not recover the six bad units in this sample). CWE-259 is where live Groq helps vs template (F1 0.000 → 0.923).

## 3) What we do not claim

- Not the full Juliet 28,881 cases.
- Not CWE-79 / 22 / 502 / 798 file folders (missing in Juliet Java 1.3; nearby ids kept).
- Not OWASP Benchmark / Big-Vul **in this Juliet-only note**. Those suites (plus Securibench Micro, find-sec-bugs, Vul4J, CVEfixes-Java-slice) are in [`six-benchmark-results.md`](six-benchmark-results.md).
- Not retrieval@Juliet.
- LLM table is **n=72**, not n=20728.
- Authored 36-unit F1=0.923 is a **different** corpus ([`research-evaluation.md`](research-evaluation.md)).

## Repro

```bash
uv run pytest
uv run cwe-vuln-eval --suite juliet-sast
uv run cwe-vuln-eval --suite juliet-llm-sample --ablation template
# GROQ_API_KEY required:
uv run cwe-vuln-eval --suite juliet-llm-sample --per-cwe 12
```
