# Six-suite Java benchmark results (measured)

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02)

**These numbers were computed by `cwe-vuln-eval` on this machine (2026-09-17). They are not invented.** Protocol: [`docs/six-benchmark-plan.md`](six-benchmark-plan.md). Authored 36-unit table: [`docs/research-evaluation.md`](research-evaluation.md). Juliet-only narrative: [`docs/benchmark-results.md`](benchmark-results.md).

## Novelty (read this first)

Measuring six public suites **does not prove 100% novelty** and is **not** a claim of “first RAG-CWE detector ever.” Related work already uses RAG, CWE catalogs, and multi-agent detection.

**Claim we can defend:** this thesis’s **method** — regex SAST **evidence** (not SAST-as-decision) + hybrid MiniLM/TF-IDF + CWE-relationship RRF + schema-bound Groq `LLMReasoner` + validator that does not require SAST agreement — scored **against these corpora and regex/template baselines**.

Regex SAST ≠ CodeQL / FindSecBugs / commercial SAST. **Public-suite LLM tables from 2026-09-17 are retracted** (gold-label leakage in prompts + silent Groq 429→template fallback). Replacement LLM numbers are the sanitized thesis eval (`uv run cwe-vuln-eval --suite thesis`, `results/thesis/`). Full-suite **regex SAST** rows below are kept.

## Advisor summary table

| Suite | Ingested n | Regex SAST F1 | LLM sample n | Template F1 | Live Groq F1 | HTTP 429 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| NIST Juliet Java v1.3 | 20728 | 0.316 | — | — | **retracted** | yes (TPD 200k; also gold-label leakage) |
| OWASP Benchmark (Java) | 2740 | 0.395 | — | — | **retracted** | silent fallback / leakage |
| Stanford Securibench Micro | 119 | 0.072 | — | — | **retracted** | silent fallback / leakage |
| Find Security Bugs test-code | 79 | 0.435 | — | — | **retracted** | silent fallback / leakage |
| Vul4J | 62 | 0.244 | — | — | **retracted** | silent fallback / leakage |
| CVEfixes-Java-slice | 92 | 0.207 | — | — | **retracted** | silent fallback / leakage |

Historical (invalid) Groq sample F1s that must not be cited: Juliet 0.733, OWASP 0.286, Securibench 0.500, Find-sec-bugs 0.364, Vul4J 0.000, CVEfixes 0.000. Those runs mixed gold tokens (`/* POTENTIAL FLAW */`, `method_bad`, `_vuln`, `real=true`) into prompts and/or scored TemplateReasoner as live Groq after 429. Raw JSON remains in `results/benchmarks/` with this retraction. Template F1s on those contaminated samples are also not used as a thesis claim.

Raw JSON: `results/benchmarks/summary.json` and per-trial `results/benchmarks/*.json`. Sanitized replacement: `results/thesis/summary.json`.

**No suite substitutions.** CVEfixes is a **documented GitHub Advisory maven slice**, not the full CVEfixes SQLite dump (too large to vendor).

## CWE {89,79,22,502,798,327} coverage (gold ids; “not present” is not faked recall)

| CWE | Juliet | OWASP | Securibench | Find-sec-bugs | Vul4J | CVEfixes-Java-slice |
| --- | --- | --- | --- | --- | --- | --- |
| 89 | present | present | present | present | **not present** | present |
| 79 | **no folder** (nearby 80/81/83 kept) | present | present | present | present | present |
| 22 | **no folder** (nearby 23/36 kept) | present | present | present | present | present |
| 502 | **not present** | **not present** | **not present** | present | present | present |
| 798 | **no folder** (nearby 259/321 kept) | **not present** | **not present** | present | **not present** | **not present** |
| 327 | present | present | **not present** | present | **not present** | **not present** |

Thesis ids missing in Juliet are **filled from other suites** (79/22 from OWASP/Securibench/FSB/Vul4J/slice; 502 from FSB/Vul4J/slice; 798 from FSB). Nearby Juliet ids were **not** relabeled.

## Per-suite provenance and label parsing

### 1. NIST Juliet Java v1.3

| Field | Recorded value |
| --- | --- |
| URL | Catalog https://samate.nist.gov/SARD/test-suites/111 ; mirror https://github.com/find-sec-bugs/juliet-test-suite.git |
| Version / commit | v1.3 / `b2c6df3733e2176fe7097e4784895c6891632b4c` |
| Date | 2026-09-17 (NIST zip HTTP 403; GitHub sparse clone) |
| License note | NIST/CAS educational suite; FSB GitHub mirror used when NIST zip blocked |
| Labels | Filename `*_bad` / `*_good*` or method-level `bad()` / `good*` (dispatcher `good()` skipped) |
| SAST | n=20728 P=0.300 R=0.334 F1=0.316 FP=3736 FN=3193 |
| LLM | **retracted** (gold-label leakage + silent Groq fallback). Replacement: sanitized Juliet pair metric in `results/thesis/`. Historical invalid F1=0.733 must not be cited. |

### 2. OWASP Benchmark (Java)

| Field | Recorded value |
| --- | --- |
| URL | https://github.com/OWASP-Benchmark/BenchmarkJava |
| Commit | `20cbf3d11123347e47ed89541e6942836def53f7` (2026-09-08 on origin) |
| Date fetched | 2026-09-17 |
| License note | OWASP Benchmark; Java headers state GNU GPL v2 |
| Labels | `expectedresults-1.2.csv`: test name, category, real vulnerability, CWE. One `BenchmarkTest*.java` = one unit |
| CWE | 89/79/22/327 present; 328 nearby hash (not relabeled); **502 and 798 not present** |
| SAST | n=2740 P=0.660 R=0.282 F1=0.395 FP=206 FN=1016 |
| LLM | **retracted** (leakage / silent fallback). Historical invalid F1=0.286 must not be cited. |

### 3. Stanford Securibench Micro

| Field | Recorded value |
| --- | --- |
| URL | https://github.com/too4words/securibench-micro |
| Commit | `6a5a72488ea830d99f9464fc1f0562c4f864214b` (2014-12-22; v1.08 tree) |
| Date fetched | 2026-09-17 |
| License note | Apache-2.0, Copyright 2006 Benjamin Livshits |
| Labels | `@servlet vuln_count` / `getVulnerabilityCount()`; 0 → not_vulnerable. CWE from description keywords else sink APIs (sql→89, File→22, PrintWriter→79). HTTP-splitting and other families skipped, not relabeled |
| CWE | 89/79/22 present; **502/798/327 not present** |
| SAST | n=119 P=0.667 R=0.038 F1=0.072 FP=2 FN=101 |
| LLM | **retracted** (all `llm_fallback_template` on the recorded run). Historical invalid F1=0.500 must not be cited. |

### 4. Find Security Bugs test-code

| Field | Recorded value |
| --- | --- |
| URL | https://github.com/find-sec-bugs/find-sec-bugs |
| Commit | `90447f7e39e529c31cf098ebade0a755b944dd91` |
| Date fetched | 2026-09-17 |
| License note | Find Security Bugs plugin samples (LGPL-style SpotBugs plugin project). Not a scored AST CSV |
| Labels | File-level under `findsecbugs-samples-java/.../testcode`. Mapped folders only. Safe/FalsePositive/Ok names → not_vulnerable. Mixed methods in one class are not split |
| CWE | **all six thesis ids present** (327 only WeakMessageDigest/DesKeyGeneration stems) |
| SAST | n=79 P=0.833 R=0.294 F1=0.435 FP=4 FN=48 |
| LLM | **retracted**. Historical invalid F1=0.364 must not be cited. |

### 5. Vul4J

| Field | Recorded value |
| --- | --- |
| URL | https://github.com/tuhh-softsec/vul4j (`dataset/vul4j_dataset.csv`) |
| Commit | `376411da11fa705019f731404de1d0679fe73537` |
| Date fetched | 2026-09-17 |
| License note | Vul4J project GPLv3 metadata; Java blobs fetched from upstream patch commits, not vendored |
| Labels | CSV `cwe_id` in the thesis set; GitHub patch parent blob = vulnerable, patch commit = fixed |
| CWE | 79/22/502 present; **89/798/327 not present** in CSV |
| SAST | n=62 P=0.500 R=0.161 F1=0.244 FP=5 FN=26 |
| LLM | **retracted**. Historical invalid F1=0.000 must not be cited. |

### 6. CVEfixes-Java-slice

| Field | Recorded value |
| --- | --- |
| URL | GitHub Advisories `https://api.github.com/advisories?ecosystem=maven` (not the full CVEfixes Zenodo dump) |
| Slice id | `n_advisories=24 pages<=3` ; manifest `data/benchmarks/cvefixes_java_slice_manifest.json` |
| Date fetched | 2026-09-17T14:01:31Z |
| License note | Public GHSA metadata + referenced GitHub commits; upstream project licenses apply to blobs |
| Labels | Advisory CWE list (thesis ids only); parent Java blob = vulnerable, patch blob = fixed |
| CWE | 89/79/22/502 present; **798/327 not present** in this slice |
| SAST | n=92 P=0.500 R=0.130 F1=0.207 FP=6 FN=40 |
| LLM | **retracted**. Historical invalid F1=0.000 must not be cited. |

## What we do not claim

- Not SOTA. Not 100% novelty. Not “first system ever.”
- Not CodeQL / FindSecBugs engine scores (we run **our** regex on **their** labeled units).
- Not full-suite Groq (except Juliet SAST which is full ingested subset).
- Not CWE-id classification accuracy (binary vulnerable vs not).
- Authored 36-unit F1=0.923 is a **different** table.

## Repro

```bash
uv run pytest
uv run cwe-vuln-eval --suite all-sast
# Sanitized LLM (Groq TPD ~200k tokens/day; expect a 1–2 calendar-day run):
uv run cwe-vuln-eval --suite thesis
```
