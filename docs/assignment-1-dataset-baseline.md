# Assignment 1: Java CWE seed dataset and SAST-style baseline

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

**seed-only — not a benchmark.** All units were authored for this thesis milestone. Metrics are from running the regex detector on those 12 files. They are not Juliet, OWASP Benchmark, or Big-Vul numbers, and they do not mean the thesis framework has been evaluated.

## Dataset

- **Language:** Java teaching units (self-contained classes).
- **Size:** 12 units.
- **CWEs:** CWE-89, CWE-79, CWE-22, CWE-502, CWE-798, CWE-327 (each appears as one vulnerable unit and one not_vulnerable unit).
- **Labels file:** `data/seed/labels.jsonl`
- **Sources:** `data/seed/java/`
- **Label fields:** `unit_id`, `cwe_id`, `path`, `split` (`train` \| `test`), `label` (`vulnerable` \| `not_vulnerable`), `notes`.

### Labeling policy

- `vulnerable` means the unit **intentionally contains** the CWE teaching pattern (for example string-concatenated SQL).
- `not_vulnerable` means a patched/safe counterpart for the same weakness class (for example `PreparedStatement`, HTML encode, path sandbox, no `ObjectInputStream`, env-based credentials, SHA-256).
- Units are pedagogical detector samples, not exploit PoCs. Hard-coded credentials are fake (`admin` / `password`). Crypto contrast is MD5 vs SHA-256. Deserialization is a tiny `readObject` call vs reading a text line.

### Deterministic 8/4 split

The split is **not** randomized. `TRAIN_UNIT_IDS` and `TEST_UNIT_IDS` in `src/cwe_vuln/dataset/seed.py` are the source of truth; `labels.jsonl` must match them.

**Train (8)** — CWE-89, CWE-79, CWE-22, CWE-502; one vulnerable and one safe each:

| unit_id | CWE | label |
| --- | --- | --- |
| `java_cwe89_sqli_concat` | CWE-89 | vulnerable |
| `java_cwe89_sqli_prepared` | CWE-89 | not_vulnerable |
| `java_cwe79_xss_unescaped` | CWE-79 | vulnerable |
| `java_cwe79_xss_encoded` | CWE-79 | not_vulnerable |
| `java_cwe22_path_concat` | CWE-22 | vulnerable |
| `java_cwe22_path_resolved` | CWE-22 | not_vulnerable |
| `java_cwe502_readobject` | CWE-502 | vulnerable |
| `java_cwe502_json_parse` | CWE-502 | not_vulnerable |

**Test (4)** — held-out CWE-798 and CWE-327; one vulnerable and one safe each:

| unit_id | CWE | label |
| --- | --- | --- |
| `java_cwe798_hardcoded` | CWE-798 | vulnerable |
| `java_cwe798_env_config` | CWE-798 | not_vulnerable |
| `java_cwe327_md5` | CWE-327 | vulnerable |
| `java_cwe327_sha256` | CWE-327 | not_vulnerable |

Train and test both mix vulnerable and not_vulnerable units. Test holds out two CWE families so the documented split is not a reshuffle of the same four pairs, but the regex rule table still includes those two families (this is still a seed, not a generalization benchmark).

## Baseline

- **Type:** regex / SAST-style pattern detector (`src/cwe_vuln/sast/detector.py`). No API key.
- **LLM stub:** Assignment 1’s `llm_detect` is skipped without `GROQ_API_KEY` / `CWE_VULN_LLM_API_KEY`, and is **not implemented in this assignment** even if a key is set. `OPENAI_API_KEY` is unused. The later pipeline reasoner is Groq `LLMReasoner` (default `openai/gpt-oss-20b`) outside Assignment 1.
- **Positive class:** `vulnerable` vs `not_vulnerable` (binary). A unit is predicted vulnerable if **any** configured rule matches.
- **Rules (seed-oriented):**
  - CWE-89: `"SELECT|INSERT|UPDATE|DELETE..."` immediately concatenated with `+`
  - CWE-79: HTML tag markup concatenated with a value that is not `htmlEncode(...)`
  - CWE-22: `new File(...)` with `+` inside the constructor argument
  - CWE-502: `ObjectInputStream` or `.readObject(`
  - CWE-798: `password` / `passwd` / `apiKey` / `secret` assigned a string literal
  - CWE-327: `getInstance("MD5"|"DES"|"DESede"|"RC4"|"SHA-1"|"SHA1")` (not SHA-256)

### How metrics are computed

On a chosen subset (overall, train, test, or one CWE):

- TP / FP / TN / FN from binary labels
- precision = TP / (TP + FP), or 0 if the denominator is 0
- recall = TP / (TP + FN), or 0 if the denominator is 0
- F1 = harmonic mean of precision and recall, or 0 if both are 0

Reproduce:

```bash
uv sync
uv run python -m cwe_vuln
```

This regenerates `results/assignment-1-baseline.json` and `results/assignment-1-baseline.md`.

## Recorded scores

From the checked-in run of `uv run python -m cwe_vuln` (regex detector on the 12 authored units).

**seed-only — not a benchmark.** Perfect scores here mean the tiny seed matches the rules, not that a detector is ready for research comparison.

| Split | Precision | Recall | F1 | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| overall | 1.000 | 1.000 | 1.000 | 6 | 0 | 6 | 0 |
| train | 1.000 | 1.000 | 1.000 | 4 | 0 | 4 | 0 |
| test | 1.000 | 1.000 | 1.000 | 2 | 0 | 2 | 0 |

Per-CWE subsets on this seed are likewise 1.000 / 1.000 / 1.000 with 0 FP and 0 FN (one TP and one TN per CWE). If a later rule change breaks that, trust the regenerated `results/` files over this table and update this section.
