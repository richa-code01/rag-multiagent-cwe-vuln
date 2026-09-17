# Public-benchmark evaluation plan (Juliet Java)

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

This document is the protocol. **No scores live here until a run writes them into** [`docs/benchmark-results.md`](benchmark-results.md). Authored 36-unit research eval remains a **different table** ([`docs/research-evaluation.md`](research-evaluation.md)).

## Goal

Score the **existing** pipeline (regex SAST evidence → hybrid CWE retrieval → Groq `LLMReasoner` / TemplateReasoner ablation → validator) on a **public** labeled suite. Pedagogical detection only: we do not write exploits.

Live path (PR #13 / `live-research`): `Pipeline.default()` requires `GROQ_API_KEY`; default model `openai/gpt-oss-20b`; `sast_disagreement` is a warning; `--offline` / `--ablation template` is TemplateReasoner.

## Suite (primary)

**NIST Juliet Test Suite for Java v1.3** (SARD test suite 111).

| Field | Planned source |
| --- | --- |
| Catalog | https://samate.nist.gov/SARD/test-suites/111 |
| Author | NSA Center for Assured Software |
| Version | Juliet Java **1.3** |
| Submission date | 01 Oct 2017 |
| Size / SHA-256 (NIST page) | 73.2 MB / `d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60` |
| Test cases (NIST page) | 28,881 |
| Official zip (try first) | `https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip` |
| Mirror if NIST blocked | Sparse clone `https://github.com/find-sec-bugs/juliet-test-suite` (Juliet Java 1.3 layout; record commit SHA) |

Download date, exact URL that succeeded, and SHA/commit go into `data/benchmarks/juliet_provenance.json` and the results doc. Binaries stay gitignored under `data/benchmarks/`.

**Executed 2026-09-17:** NIST zip **HTTP 403**. Next action: sparse clone of `https://github.com/find-sec-bugs/juliet-test-suite.git` at commit `b2c6df3733e2176fe7097e4784895c6891632b4c`. LLM sample executed at **12 units/CWE × 6 ids (n=72)** rather than 20, for Groq free-tier; no 429 occurred. See [`benchmark-results.md`](benchmark-results.md).

**OWASP Benchmark** is optional and **only** if Juliet ingest of the mapped families fails. Default: skip.

**Retrieval@Juliet:** skip unless we can build queries whose gold CWE ids exist in our curated KB. Nearby Juliet ids (80, 23, 259, 328, …) are **not** in `SEED_CWE_IDS`, so Recall@K against Juliet gold would be structurally misleading. Protocol: skip and say so.

## CWE mapping (do not silently relabel)

Thesis detector CWEs: **89, 79, 22, 502, 798, 327**.

Juliet Java 1.3 `src/testcases/` (inspected via GitHub API listing of `find-sec-bugs/juliet-test-suite`, 2026-09-17):

| Thesis CWE | Juliet folder | Action |
| --- | --- | --- |
| CWE-89 | `CWE89_SQL_Injection` | Ingest. Gold `cwe_id=CWE-89`. |
| CWE-79 | **no `CWE79_*` folder** | Do not invent CWE-79 labels. Ingest XSS **nearby**: `CWE80_XSS`, `CWE81_XSS_Error_Message`, `CWE83_XSS_Attribute`. Gold stays CWE-80/81/83. |
| CWE-22 | **no `CWE22_*` folder** | Ingest path **nearby**: `CWE23_Relative_Path_Traversal`, `CWE36_Absolute_Path_Traversal`. Gold stays CWE-23/36. |
| CWE-502 | **no `CWE502_*` folder** | Document missing. Do not substitute a different weakness. |
| CWE-798 | **no `CWE798_*` folder** | Ingest hardcoded-secret **nearby**: `CWE259_Hard_Coded_Password`, `CWE321_Hard_Coded_Cryptographic_Key`. Gold stays CWE-259/321. |
| CWE-327 | `CWE327_Use_Broken_Crypto` | Ingest. Gold `cwe_id=CWE-327`. |
| (nearby hash) | `CWE328_Reversible_One_Way_Hash` | Ingest **without** relabeling to CWE-327. |

Per-CWE tables use **Juliet gold ids**, not our six-id detector taxonomy.

## Units (adapter)

Juliet Java often puts `bad()` and `good*()` in one file. Scoring the **whole file** would mix gold labels. Adapter `cwe_vuln.dataset.juliet`:

1. Skip `Main.java`, `ServletMain.java`, `*_base.java`, helpers without `bad`/`good` methods.
2. Filename `*_bad.java` → one unit, label `vulnerable`.
3. Filename containing `_good` (`_goodG2B`, `_goodB2G`, …) → one unit, label `not_vulnerable`.
4. Mixed files: extract `bad()` → `vulnerable`; extract `goodG2B` / `goodB2G` / `good1` / `good2` / … → `not_vulnerable`. Skip the `good()` dispatcher that only calls those methods.
5. Wrap extracted methods in a synthetic class plus the file’s import block so regex SAST still sees Java-like source. `SeedUnit.corpus=juliet`, `split=juliet`. Do not flatten orchestrator/reasoner/validator.

Ground truth: Juliet good = `not_vulnerable`, Juliet bad = `vulnerable`. Binary detection (vulnerable = positive). This is **not** CWE-id classification accuracy.

## Sampling and Groq budget

Free-tier Groq cannot score tens of thousands of units.

1. **Full regex SAST** on every mapped unit we ingest. Cheap. Report P/R/F1/FP/FN overall + per Juliet CWE. Exact **n**. Label tables: “Juliet Java v1.3, CWE subset Y, n=…”.
2. **Stratified LLM sample** written to `data/benchmarks/juliet_llm_sample.json` (committed): seed **13**, target **20 units per ingested Juliet CWE id** (10 bad / 10 good; fewer if a family is smaller). Families for the LLM table = those with ingestable units after mapping. If Groq **429**, shrink (12 then 8 then 4 per CWE), sleep, log. Default model `openai/gpt-oss-20b`. Never print `gsk_`.
3. **Same sample**, TemplateReasoner `--ablation template` / `--offline`. Comparison table. Not the system of record.
4. Do **not** claim the full 28,881-case suite if we subsampled the LLM path.

## Metrics

Same `binary_metrics` helper as research eval. Overall + per CWE. Pipeline trials also record validator pass rate, `sast_disagreement` warnings, reasoner/path counts, and unit-level errors (redacted).

## CLI

```bash
uv run cwe-vuln-eval --suite juliet-sast
uv run cwe-vuln-eval --suite juliet-llm-sample --ablation template   # no key
uv run cwe-vuln-eval --suite juliet-llm-sample                     # GROQ_API_KEY
```

Outputs: `results/benchmarks/*.json`, [`docs/benchmark-results.md`](benchmark-results.md).

## Tests

Tiny Juliet-shaped fixtures under `tests/fixtures/juliet/` (not the full suite). Assert good/bad parsing and that mixed files are not labeled from the filename alone.

## Honesty

- Authored 36-unit numbers stay in the research table; Juliet numbers stay in the Juliet table.
- Missing Juliet folders (79, 22, 502, 798) are gaps, not silent remaps.
- Regex rules were written for pedagogical seed Java; Juliet scores may be low. That is a valid measurement.
- If download or scoring fails, results record the failure and the next action (mirror, shrink, skip).
