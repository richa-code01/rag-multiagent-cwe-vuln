# RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases

**Student:** Richa Verma (25MCSS02)
**Advisor:** Dr. Akshay Pandey
**Current milestone:** Juliet Java public-benchmark subset (`benchmark-eval`)

Canonical context: [`rag-multiagent-context.txt`](rag-multiagent-context.txt)
Sequence: [`docs/advisor-phase-plan.md`](docs/advisor-phase-plan.md) · Architecture: [`docs/architecture.md`](docs/architecture.md) · Plan: [`docs/implementation-plan.md`](docs/implementation-plan.md)

Authored 36-unit scores and Juliet scores are **different tables**. Do not mix them.

## Contribution (what this thesis actually claims)

A RAG-augmented multi-agent detector for **six Java CWEs** in which:

1. SAST-style regex rules emit **evidence** (not the final vulnerability decision)
2. Hybrid MiniLM + SAST ids + CWE relationship/RRF retrieves CWE knowledge
3. A Groq LLM produces Assignment-4 schema explanations grounded in the unit, evidence, and retrieval hits
4. A validator checks schema, CWE-in-KB, cited lines, and JSON consistency — **not** SAST agreement
5. On an authored 24-unit FP/FN trap split, regex SAST and TemplateReasoner fail (F1=0) and the live LLM recovers most cases

This is **not** a claim of SOTA, 100% novelty, or that the authored 36-unit trap split is Juliet. RAG + CWE + multi-agent detection already exists in related work. The contribution is this specific, runnable composition, the honest trap-split contrast, and a **mapped Juliet Java v1.3 subset** evaluation (not the full 28,881-case suite).

## Problem statement

This thesis studies **explainable** vulnerability detection: map a Java unit to a CWE and ground that mapping in a CWE knowledge base. Assignments 1–4 and the wired pipeline are complete. The **system of record** is live Groq `LLMReasoner`. SAST-only and TemplateReasoner scored F1=0 on the 24-unit research split; they remain opt-in ablations for comparison tables, not the deployed default.

## Pipeline

```text
Java SeedUnit
    → SAST Evidence[]              evidence extraction only (regex rules)
    → hybrid RankedHit[]           MiniLM cosine (TF-IDF fallback) + SAST + CWE relationships (RRF)
    → ReasoningResult              Groq LLMReasoner (A4 schema); --offline uses TemplateReasoner
    → ValidationReport             schema / KB / cited lines / JSON consistency
                                   (sast_disagreement is a warning, not a fail)
    → metrics vs labels
```

End-to-end:

```bash
uv sync
uv run pytest
# requires GROQ_API_KEY in gitignored .env
uv run cwe-vuln-pipeline
uv run cwe-vuln-eval --suite research
```

Default pipeline split is the **4 test units**. `uv run cwe-vuln-pipeline --split all` runs all 12. Writes `results/framework-seed.json`.

Without `GROQ_API_KEY` the default CLI **exits non-zero** and tells you to set the key. Paper ablations:

```bash
uv run cwe-vuln-pipeline --offline
uv run cwe-vuln-eval --suite research --ablation template
```

**Research split** (24 held-out authored traps, **authored corpus — not Juliet**): SAST/template P=R=F1=0.000 (12 FP / 12 FN); live Groq then_llm P=0.857 R=1.000 F1=0.923 (2 FP / 0 FN), validator **24/24**. Details: [`docs/research-evaluation.md`](docs/research-evaluation.md).

**Juliet Java v1.3** (mapped/nearby CWE folders, **n=20728 SAST**; live Groq on stratified sample **n=72**): regex SAST P=0.300 R=0.334 F1=0.316; sample template F1=0.552; sample live Groq F1=0.733. NIST zip returned HTTP 403; GitHub mirror commit `b2c6df3`. CWE-79/22/502/798 folders are missing; nearby ids were not relabeled. Details: [`docs/benchmark-results.md`](docs/benchmark-results.md).

## MiniLM embeddings

First retrieve/eval (or first pipeline run outside pytest) downloads `all-MiniLM-L6-v2` into `.cache/sentence-transformers/` (gitignored). Reruns load from that cache. If the download or import fails, retrieval falls back to TF-IDF and records `embedder=tfidf_fallback`. Unit tests never require the download.

```bash
uv run cwe-vuln-retrieve --eval
```

Recorded seed-only retrieval (18 queries, embedder=`minilm`): neural R@1=0.944 R@3=1.000 R@5=1.000 MRR=0.972 vs lexical TF-IDF R@1=0.778 R@3=0.944 R@5=0.944 MRR=0.868. Hybrid RRF matches neural on this seed. **seed-only — not a benchmark.**

Expanded authored queries (48, **not a public benchmark**): TF-IDF R@1=0.646 MRR=0.794; MiniLM R@1=0.812 MRR=0.894; hybrid RRF R@1=0.854 MRR=0.917. Hybrid still helps R@1/MRR on the expanded set.

## Live LLM (Groq)

Default `cwe-vuln-pipeline` and `cwe-vuln-eval --suite research` **require** a Groq key. Copy `.env.example` to `.env` (gitignored) or export:

```bash
export GROQ_API_KEY=...                 # or CWE_VULN_LLM_API_KEY
# optional:
# export CWE_VULN_LLM_MODEL=openai/gpt-oss-20b
# export CWE_VULN_LLM_BASE_URL=https://api.groq.com/openai/v1
uv run cwe-vuln-pipeline
```

| Env | Role |
| --- | --- |
| `GROQ_API_KEY` | Required for the default live path |
| `CWE_VULN_LLM_API_KEY` | Optional override |
| `CWE_VULN_LLM_MODEL` | Default `openai/gpt-oss-20b` (Groq free-tier replacement for retired `llama-3.1-8b-instant`) |
| `CWE_VULN_LLM_BASE_URL` | Default `https://api.groq.com/openai/v1` |

Default knobs: `use_llm_if_available=True`, `skip_llm_when_sast_hits=False`. Paths are `sast_then_llm` / `hybrid_retrieve_then_llm`. Invalid JSON is retried once, then `reasoner=llm_fallback_template`. No exploit generation.

## Honest status

| Piece | Status |
| --- | --- |
| Java seed (12 units, 6 CWEs, 8/4 split) | Done ([PR #1](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/1)) |
| Regex baseline + P/R/F1 | Done (A1) `uv run cwe-vuln` |
| CWE knowledge store + query API | Done ([PR #2](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/2)) `uv run cwe-vuln-kb demo` |
| Hybrid retrieval (TF-IDF + SAST + relationships) | Done ([PR #3](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/3)) `uv run cwe-vuln-retrieve` |
| Neural embeddings / MiniLM | Done (`all-MiniLM-L6-v2`, TF-IDF fallback) |
| Reasoning output JSON Schema | Done ([PR #4](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/4)) |
| SAST evidence objects | Done ([PR #5](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/5)) |
| Template reasoning agent | Done ([PR #6](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/6)) — **ablation only** |
| Validator | Done ([PR #7](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/7)); SAST-iff-vulnerable rule **removed** on `live-research` |
| Cost-aware orchestrator | Done ([PR #8](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/8)); default is live Groq |
| Framework CLI on the seed | Done ([PR #9](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/9)) |
| Layered packages (`models`, `dataset`, `sast`, …) | Done ([PR #10](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/10)) |
| Live LLM reasoner | Done — Groq `LLMReasoner`; default path **fails** without `GROQ_API_KEY` |
| Research evaluation (authored 36-unit corpus) | Done — `uv run cwe-vuln-eval --suite research` |
| Live research default | Groq required; validator no longer tied to SAST |
| Juliet Java v1.3 mapped eval | Done — `uv run cwe-vuln-eval --suite juliet-sast` / `--suite juliet-llm-sample` |

Authored 36-unit metrics live in [`docs/research-evaluation.md`](docs/research-evaluation.md). Juliet metrics live in [`docs/benchmark-results.md`](docs/benchmark-results.md). Those tables are not interchangeable.

## Seed (Assignment 1)

`data/seed/java/` + `data/seed/labels.jsonl`. Split lists in `src/cwe_vuln/dataset/seed.py`.

| Split | n | CWEs | Labels |
| --- | --- | --- | --- |
| train | 8 | 89, 79, 22, 502 (vuln+safe each) | 4 / 4 |
| test | 4 | 798, 327 (vuln+safe each) | 2 / 2 |

A1 regex-only overall (**seed-only**): P=1.000 R=1.000 F1=1.000 FP=0 FN=0.

## Research corpus

`data/research/java/` + `data/research/labels.jsonl`. Assignment 8/4 is unchanged.

| Split | n | Role |
| --- | ---: | --- |
| seed train/test | 8 / 4 | Assignment 1 plumbing |
| research_test | 24 | held-out FP/FN traps |
| authored total | 36 | **not a public benchmark** |

`uv run cwe-vuln-eval --suite research` writes `results/experiments/` and `results/research-eval-summary.json`.

## Juliet (public benchmark subset)

Protocol: [`docs/benchmark-plan.md`](docs/benchmark-plan.md). Measured results: [`docs/benchmark-results.md`](docs/benchmark-results.md).

```bash
uv run cwe-vuln-eval --suite juliet-sast
uv run cwe-vuln-eval --suite juliet-llm-sample --per-cwe 12
```

Do not mix these numbers with the 36-unit authored table.

## Knowledge / retrieval / schema

- Knowledge: `uv run cwe-vuln-kb demo` — [`docs/assignment-2-cwe-knowledge.md`](docs/assignment-2-cwe-knowledge.md)
- Retrieval (18 queries, **seed-only**, MiniLM): hybrid R@1=0.944 R@3=1.000 R@5=1.000 MRR=0.972 — [`docs/assignment-3-hybrid-retrieval.md`](docs/assignment-3-hybrid-retrieval.md)
- Schema: `uv run cwe-vuln-schema data/schema_samples/vulnerable.json` — [`docs/assignment-4-output-schema.md`](docs/assignment-4-output-schema.md)
- Evidence: `uv run cwe-vuln-evidence --unit-id java_cwe89_sqli_concat` — [`docs/sast-evidence.md`](docs/sast-evidence.md)

## Install

Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest
uv run cwe-vuln-pipeline
uv run cwe-vuln-eval --suite research
```
