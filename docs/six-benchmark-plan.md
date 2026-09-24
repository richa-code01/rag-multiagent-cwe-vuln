# Six-suite public benchmark evaluation plan

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

This is the **protocol**. Measured numbers belong in [`docs/six-benchmark-results.md`](six-benchmark-results.md) and `results/benchmarks/summary.json` after a run. Do not invent scores.

## Goal

Score the **existing** pipeline (regex SAST evidence → hybrid CWE retrieval → Groq `LLMReasoner` / TemplateReasoner ablation → validator) on **at least six named public/industry-style Java vulnerability suites**, so the advisor can see more than the authored 36-unit seed and a single Juliet subset.

Pedagogical detection only: we do not write exploits.

## Novelty (do not overclaim)

Running six suites **does not prove 100% novelty** and is **not** a claim of “first RAG-CWE detector ever.” Related work already combines RAG, CWE knowledge, and multi-agent detection.

**Defendable novelty claim:** this thesis’s **method** — SAST evidence objects (not SAST-as-decision) + hybrid MiniLM/TF-IDF + CWE-relationship RRF retrieval + schema-bound Groq `LLMReasoner` + validator that does not require SAST agreement — measured **against these corpora and regex/template baselines**. Authored 36-unit numbers, Juliet numbers, and other-suite numbers stay in **separate rows** of the six-suite table (plus the existing research table).

## Detector CWEs

Thesis detector ids: **{89, 79, 22, 502, 798, 327}**.

If a suite has **no files** for a CWE, the results table says **“not present”**. Do not invent recall. Do not silently relabel a nearby CWE to a missing thesis id. Nearby ids (e.g. Juliet CWE-80 for XSS) keep their gold id; they may be **grouped in narrative** as covering a family (XSS / path / secrets) but per-CWE metrics use gold ids.

Juliet Java v1.3 is missing folders for 79/22/502/798. Protocol: **fill those thesis ids from other suites** (OWASP 79/22, find-sec-bugs 502/798, etc.) rather than relabeling Juliet.

## The six suites (names are fixed)

| # | CLI `--suite` name | Planned source | Gold labels | License note (record actual after clone) |
| --- | --- | --- | --- | --- |
| 1 | `juliet` / `juliet-sast` | NIST Juliet Java **v1.3** (SARD 111); GitHub mirror if NIST zip 403 | Method/filename good=benign, bad=vuln | NIST / CAS educational; mirror `find-sec-bugs/juliet-test-suite` |
| 2 | `owasp-benchmark` | Official [OWASP-Benchmark/BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) | `expectedresults-1.2.csv`: test name, category, real vulnerability, CWE | OWASP Benchmark license (record from repo) |
| 3 | `securibench-micro` | Stanford Securibench Micro ([too4words/securibench-micro](https://github.com/too4words/securibench-micro)) | Per-file sink/CWE comments + documented category map | Apache-2.0 (Livshits) |
| 4 | `find-sec-bugs` | [find-sec-bugs](https://github.com/find-sec-bugs/find-sec-bugs) `findsecbugs-samples-java` test-code | Directory + `@ExpectWarning` / Safe* filenames; map bug type → CWE | LGPL plugin samples |
| 5 | `vul4j` | [tuhh-softsec/vul4j](https://github.com/tuhh-softsec/vul4j) `dataset/vul4j_dataset.csv` | CSV `cwe_id`; vuln file at patch parent, fixed file at patch commit | Dataset paper / repo license |
| 6 | `cvefixes-java-slice` | CVEfixes Java subset **or** documented GitHub Advisory/CVE Java slice with gold CWE | Patch parent = vuln, patch commit = fixed | CVEfixes CC-BY-4.0-style (record exact); slice n and commit in provenance |

If a download fails, **substitute a documented Java-CWE corpus**, keep six named rows, and write the substitution in results (URL, commit, n, why).

### Juliet (already ingested)

Keep the measured SAST **n=20728** table. Do not re-download unless the tree is missing. LLM sample may reuse `data/benchmarks/juliet_llm_sample.json` (n=72, seed=13). CWE-502 remains **not present** in Juliet.

### OWASP Benchmark

Sparse-clone `src/main/java/org/owasp/benchmark/testcode` + `expectedresults-1.2.csv`. One Java file = one unit. `real vulnerability=true` → `vulnerable`, else `not_vulnerable`. Gold CWE from CSV column. Ingest thesis ids **and** nearby scored categories that appear (e.g. CWE-328 hash) **without relabeling**. OWASP typically **does not** score CWE-502 or CWE-798 — say not present.

### Securibench Micro

Clone `src/securibench/micro`. Units are servlet test files. Parse Livshits-style `@sinks` / vulnerability comments when present; otherwise map package/category (sql → 89, xss → 79, path/pred file sinks → 22). Files documented as having **zero sinks** are `not_vulnerable`. Do not guess CWE-502/798/327 if absent.

### Find Security Bugs test-code

Sparse-clone `findsecbugs-samples-java/src/test/java/testcode`. Map folders/bug types:

| Family | Example paths / patterns | Gold CWE |
| --- | --- | --- |
| SQL | `sql`, `sqli`, `JDBC` | CWE-89 |
| XSS | `xss` | CWE-79 |
| Path | `path`, `file`, `PathTraversal` | CWE-22 |
| Deserialize | `serial`, `deserialize`, `ObjectInputStream` samples | CWE-502 |
| Hardcoded secrets | `password`, `HardCode` | CWE-798 |
| Weak crypto | `crypto` DES/MD5/RC4 samples | CWE-327 |

`Safe`, `Ok`, `FalsePositive`, `DesireNoWarning` → `not_vulnerable` when that is the file’s intent; `@ExpectWarning` / non-safe samples → `vulnerable`. Skip helpers with no signal.

### Vul4J

Do **not** clone every upstream project as a tarball. Parse `vul4j_dataset.csv`. For rows whose `cwe_id` is a thesis CWE (or an explicit nearby id kept as gold), fetch **changed Java files** at `human_patch` parent (vulnerable) and at the patch commit (fixed) via GitHub raw/API. One file version = one unit. If a CWE has zero rows, **not present**. Record how many CSV rows vs how many files actually fetched.

### CVEfixes Java slice

If the full CVEfixes SQLite dump is too large to vendor: build **CVEfixes-Java-slice** from GitHub Security Advisories (`ecosystem=maven`) and/or NVD CVE records that include a CWE in the thesis set **and** a GitHub commit with `.java` file changes. Same vuln/fixed pairing as Vul4J. Provenance must include: advisory/CVE ids, commit SHAs, date fetched, exact **n**, and that this is a **slice**, not the full CVEfixes database.

## Units

Adapters emit `SeedUnit` (`corpus=<suite>`, `split=<suite>`). Binary gold: vulnerable = positive. This is **not** CWE-id classification accuracy (a detector may fire a different CWE regex; the label is still vuln/benign).

## Protocol per suite

1. **Adapter** → units (good/bad or vuln/fixed).
2. **Full regex SAST** on every ingested unit. Report P/R/F1/FP/FN overall + per gold CWE when labels exist. Exact **n**.
3. **Deterministic stratified LLM sample** (seed **13**, target **8–16 units/suite**, half vuln / half benign when both exist; shrink rather than invent). Write `data/benchmarks/<suite>_llm_sample.json` with unit ids. Live Groq: sequential, backoff on **429**, model `openai/gpt-oss-20b`. Never print `gsk_`.
4. **Template ablation** on the **same** sample (`--ablation template`).
5. One summary table in [`docs/six-benchmark-results.md`](six-benchmark-results.md) + `results/benchmarks/summary.json`.

Juliet SAST stays the large-n row. Other suites may be smaller; report exact n.

## CLI

```bash
uv run cwe-vuln-eval --suite juliet                 # alias: juliet-sast
uv run cwe-vuln-eval --suite owasp-benchmark
uv run cwe-vuln-eval --suite securibench-micro
uv run cwe-vuln-eval --suite find-sec-bugs
uv run cwe-vuln-eval --suite vul4j
uv run cwe-vuln-eval --suite cvefixes-java-slice
uv run cwe-vuln-eval --suite <name>-llm-sample              # GROQ_API_KEY
uv run cwe-vuln-eval --suite <name>-llm-sample --ablation template
```

## Tests

Tiny fixtures under `tests/fixtures/<suite>/`. Mapper tests: gold parse, no silent CWE relabel. `uv run pytest` green. Tests never call live Groq or require full suite trees.

## Git

Gitignore raw trees under `data/benchmarks/**` (except committed manifests `*_llm_sample.json`, `*_provenance.json`). Never commit `.env`, keys, or huge zips.

## Honesty checklist

- No invented numbers or fake citations.
- LLM sample ≠ full suite.
- Regex SAST ≠ CodeQL / FindSecBugs / commercial SAST.
- Six-suite eval ≠ proof of 100% novelty.
- Missing CWE in a suite = “not present.”
