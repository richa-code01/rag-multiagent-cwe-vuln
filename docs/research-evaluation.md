# Research evaluation — authored expanded corpus

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

**This evaluation is on an authored corpus — not Juliet.**
Juliet Java v1.3 mapped-subset numbers live in [`docs/benchmark-results.md`](benchmark-results.md) (SAST n=20728; LLM sample n=72). Six named public suites live in [`docs/six-benchmark-results.md`](six-benchmark-results.md). Do not copy those figures into this table.
It is not Juliet, OWASP Benchmark, Vul4J, or Big-Vul. Numbers below were computed from
units under `data/seed/java/` and `data/research/java/` with labels in the
manifests. Related-work names, if mentioned, are papers already in
`research-papers/` or well-known public system names without invented venues.

**Claim we can defend:** a RAG-augmented multi-agent detector for six Java CWEs
in which (1) SAST-style rules emit evidence, (2) hybrid MiniLM + relationship/RRF
retrieves CWE knowledge, (3) a Groq LLM produces A4-schema explanations, (4) a
validator checks schema/lines/KB not SAST agreement, (5) on this 24-unit FP/FN
trap split, regex/template fail and live LLM recovers most cases.

**Do not claim:** SOTA, six-suite numbers as this table, 100% novelty, that template/SAST
are the deployed system, or that this evaluation is a public benchmark.

Repro: `uv run pytest` (71 passed, Groq mocked / keys cleared) then
`uv run cwe-vuln-eval --suite research` (requires `GROQ_API_KEY`).
Ablation without a key: `uv run cwe-vuln-eval --suite research --ablation template`.
Advisor short table: [`results/research-eval-summary.md`](../results/research-eval-summary.md).

## Protocol

Goal: make evaluation **able to fail**. The Assignment 1 12-unit seed is a
pedagogical 8/4 split on which regex SAST scores P=R=F1=1.0. That is too easy
to support a research claim. This study keeps that seed as the assignment
baseline and adds a held-out **research test** of FP and FN traps for CWE-89,
79, 22, 502, 798, and 327.

The **system of record** is live Groq `LLMReasoner` (`openai/gpt-oss-20b`).
SAST-only and TemplateReasoner scored F1=0 on research_test; they are kept as
opt-in ablations (`--ablation template`), not the default CLI path.

Comparisons on the same held-out research test (n=24) unless noted:

1. SAST / regex only (ablation; F1=0 by construction)
2. Template reasoner, no LLM (ablation; follows SAST 1:1)
3. Live Groq LLM reasoner (`openai/gpt-oss-20b`; probe recorded) — **system of record**
4. Retrieval: TF-IDF vs MiniLM vs hybrid RRF on 48 authored queries
5. Top-K ∈ {1, 3, 5, 10} (Recall@K, MRR)
6. Cost path `skip_llm` kept as an opt-in ablation (`--ablation skip-llm`), not the default

Each trial is a JSON file in `results/experiments/`. Failures are kept.

## Corpus

| Slice | n | Location | Role |
| --- | ---: | --- | --- |
| Assignment seed | 12 | `data/seed/java/` + `data/seed/labels.jsonl` | A1 8/4 split; tests still assert 8 train / 4 test |
| Research test (held-out) | 24 | `data/research/java/` + `data/research/labels.jsonl` | 12 FP traps + 12 FN traps (2+2 per CWE) |
| Full authored corpus | 36 | seed ∪ research | Union; **not a public benchmark** |

Deterministic split: seed train/test ids stay in `src/cwe_vuln/dataset/seed.py`.
Research test ids are `RESEARCH_TEST_UNIT_IDS` in `src/cwe_vuln/dataset/research.py`.
Research “train” for narrative is the original 12. Retrieval ranks CWE documents,
not Java units.

Trap types:

- **FP trap:** labeled `not_vulnerable`, but a configured regex fires (comment
  tokens, compile-time constants, encode-then-concat, sentinel then env, SHA-256
  with a banned-MD5 comment, trusted round-trip).
- **FN trap:** labeled `vulnerable`, but no configured regex fires (StringBuilder /
  split SQL, `getParameter` / `concat`, two-arg `File` / `Paths.get`, helper
  reflection deserialization, `char[]` / fragment token, MD5 via variable or
  `"MD"+"5"`).

Java units are pedagogical detection samples, not exploit PoCs. Gold labels are
**not** written into research class names or javadocs (see trial log).

## Metrics

Detection (vulnerable=positive): P, R, F1, TP/FP/TN/FN, overall and per-CWE.
Confusion: `unit_id`, true label, predicted, SAST hit, trap type, why.

Retrieval: R@1/R@3/R@5/R@10, MRR on 18 assignment queries plus
`data/retrieval/research_queries.jsonl` (48 total).

Explainability: % of reasoner outputs that pass the Assignment 4 validator
(schema, CWE-in-KB, cited lines, JSON consistency). SAST disagreement is a
**warning** and does not fail the unit. Also % of `cited_lines` checks that
pass after LLM snippet normalize.

## Trial log

| trial_id | status | notes |
| --- | --- | --- |
| `sast_fn_traps_javadoc_false_start` | failed | First FN drafts matched regex via javadoc tokens. Fix: neutralize FN comments. |
| `sast_fp_traps_javadoc_rewrite_regression` | failed | After stripping gold labels, two FP hits lived only in javadoc. Fix: comment tokens without gold labels. |
| `llm_then_research_test_label_leak` | invalid | First live Groq run P=R=F1=1.0 with `Safe`/`Vulnerable` in class names and javadocs. Not used as a detection claim. |
| `llm_skip_when_sast_research_test_label_leak` | invalid | Same leakage on the skip_llm path. Discarded. |
| `sast_regex_research_test` | ok | 12 FP + 12 FN by construction. Ablation, not the system of record. |
| `template_skip_llm_research_test` | ok | Template follows SAST 1:1. Ablation. |
| `llm_then_research_test` | ok | Live Groq `openai/gpt-oss-20b` (probe_ok). **System of record.** |
| `llm_then_seed_test` | ok | Live Groq on the 4-unit assignment test split (seed-only). |
| `llm_skip_when_sast_research_test` | ok | Kept as cost-path ablation JSON. Not the default orchestrator policy. |
| `retrieval_*_expanded` | ok | 48 queries, embedder=`minilm`. |

Default Groq model `openai/gpt-oss-20b` probed successfully; no 404 fallback was
needed on the recorded run. `llama-3.1-8b-instant` was retired on Groq’s free
tier and is not used. Rate limits did not fire on the recorded run.

## Detection tables (authored corpus — not a public benchmark)

Held-out **research test (24 units)**. Seed-only 12-unit scores stay in
`results/assignment-1-baseline.json` (P=R=F1=1.000) and
`results/framework-seed*.json`.

| System | Precision | Recall | F1 | FP | FN | n | Role |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| SAST / regex only | 0.000 | 0.000 | 0.000 | 12 | 12 | 24 | ablation |
| Template reasoner, no LLM | 0.000 | 0.000 | 0.000 | 12 | 12 | 24 | ablation |
| Live Groq then_llm | 0.857 | 1.000 | 0.923 | 2 | 0 | 24 | **system of record** |
| Cost path skip_llm | 0.500 | 1.000 | 0.667 | 12 | 0 | 24 | ablation |

Per-CWE SAST on research_test is 2 FP + 2 FN for every family (support 4).

then_llm per-CWE: CWE-89/79/502/327 P=R=F1=1.0; CWE-22 and CWE-798 each have
1 FP (const `File` concat; sentinel `password="use-env"` then getenv).

## Retrieval tables (authored corpus — not a public benchmark)

48 labeled queries (18 assignment + 30 research). Embedder=`minilm`.

| System | R@1 | R@3 | R@5 | R@10 | MRR |
| --- | ---: | ---: | ---: | ---: | ---: |
| lexical TF-IDF | 0.646 | 0.917 | 0.938 | 1.000 | 0.794 |
| MiniLM only | 0.812 | 0.979 | 1.000 | 1.000 | 0.894 |
| hybrid RRF | 0.854 | 0.958 | 1.000 | 1.000 | 0.917 |
| SAST id signal | 0.375 | 0.375 | 0.375 | 0.375 | 0.375 |

Hybrid still helps vs MiniLM on R@1 (0.854 vs 0.812) and MRR (0.917 vs 0.894).
At R@3 MiniLM is slightly higher (0.979 vs 0.958). Both reach R@5=1.000.
Assignment-only 18-query MiniLM numbers remain in `results/assignment-3-retrieval.json`.

## Error analysis

SAST/template errors are exactly the trap design: every FP trap is a false
positive, every FN trap is a false negative. That is why they are not the
system of record.

then_llm (live Groq, 24/24 `reasoner=llm`, paths 12 `sast_then_llm` / 12
`hybrid_retrieve_then_llm`):

- Recovers all 12 SAST misses (FN traps).
- Still follows SAST on two FP traps: `java_cwe22_t01_const_concat` (constant
  relative file name concatenated into `new File`) and
  `java_cwe798_t01_sentinel_then_env` (sentinel `password="use-env"` overwritten
  from the environment).
- Validator previously **2/24 (8.3%)** because Assignment 7 required
  `vulnerable` iff SAST evidence is non-empty. That contract punished Groq for
  correctly catching SAST FNs. After the live-research fix, then_llm validator
  pass is **24/24 (100%)**. `sast_disagreement` warnings fired on **22/24**
  units (12 FN overrides + 10 correctly rejected FP traps). Those warnings do
  not fail the unit. Cited lines after normalize: **24/24 (100%)**.

skip_llm (prior ablation JSON, not re-run under the new validator): recall 1.0
because FN traps have no SAST hit and therefore reach the LLM; precision 0.5
because all 12 FP traps keep the template/SAST decision. Validator **12/24**
on that file still reflects the old SAST-tied contract.

## Limitations

- Authored pedagogical corpus, small N (36 units; 24 held-out; 48 queries).
- Regex rules and traps were written by the same authors; risk of overfitting
  to this rule set.
- Residual cues (CWE id in `unit_id`, notes used as retrieval queries) remain;
  class-name gold labels were removed after the leaked trial.
- Curated CWE store, not a full MITRE dump.
- Live Groq free-tier: recorded runs used `openai/gpt-oss-20b` without
  404/rate-limit; `llama-3.1-8b-instant` is retired and must not be the default.
- No claim of industry-benchmark performance.

## Advisor summary

See `results/research-eval-summary.json` and `results/research-eval-summary.md`.
Live pipeline: `uv run cwe-vuln-pipeline` (requires `GROQ_API_KEY`).
Research evaluation: `uv run cwe-vuln-eval --suite research`.
Paper contrast without a live call: `uv run cwe-vuln-eval --ablation template`.
