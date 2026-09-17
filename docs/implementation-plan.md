# Implementation plan

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

This plan records two executed slices: `modular-layout` (PR #10, layered packages) and `embeddings-llm` (MiniLM + Groq LLM with offline fallback). Earlier sections are a **snapshot of `main` after PRs 1–9**; they are not current status. Current capability is in [Embeddings + live LLM](#embeddings--live-llm-branch-embeddings-llm) and [Executed (`embeddings-llm`)](#executed-embeddings-llm-2026-09-17). It is not a product roadmap.

## Snapshot after PRs 1–9 (before modular layout and embeddings-llm)

Merged and runnable at that snapshot:

| PR | What exists | Honest limit |
| --- | --- | --- |
| #1 | 12 Java seed units, 6 CWEs, 8/4 split, regex baseline, binary P/R/F1 | seed-only, not a benchmark |
| #2 | curated `data/cwe/knowledge.json` + `CWEKnowledgeBase` query API | teaching subset, not a MITRE dump |
| #3 | TF-IDF + SAST ids + CWE relationship expansion, RRF hybrid | lexical only on this snapshot; MiniLM landed later on `embeddings-llm` |
| #4 | Draft 2020-12 `schemas/reasoning_output.schema.json` + samples | schema only |
| #5 | `Evidence` spans from regex matches | CWE names still come from knowledge |
| #6 | `TemplateReasoner` → schema-valid JSON | no LLM call |
| #7 | schema + KB id + cited lines + decision vs evidence | no retrieval |
| #8 | `Pipeline` SAST-first, skip LLM without key / when evidence exists | skip policy only |
| #9 | `cwe-vuln-pipeline` CLI, `results/framework-seed.json` | test split 4 units; `--split all` exists |

Recorded seed-only metrics (read from `results/`, not invented):

- A1 detection (12 units): P=1.000 R=1.000 F1=1.000 tp=6 fp=0 tn=6 fn=0
- A3 hybrid_rrf (18 queries): R@1=0.7778 R@3=0.9444 R@5=1.0 MRR=0.8722
- Framework test split (4 units, **seed-only**, live Groq): P=1.0 R=1.0 F1=1.0 fp=0 fn=0, validation 4/4; paths `sast_then_llm=2`, `hybrid_retrieve_then_llm=2`, reasoner `llm`

Working tree at plan time: `main` is still a **flat** `src/cwe_vuln/*.py` dump. A partial restructure has started on `modular-layout` (`models/`, `dataset/`, `knowledge/`, `sast/`, `retrieval/index.py`) but old sibling modules and flat tests remain. That mixed tree is **not** the target; it will be finished or discarded into the layered layout below.

Not yet on that snapshot of `main`:

- Neural / MiniLM embeddings — **initially skipped, then landed in `embeddings-llm`**
- Live LLM reasoner — **initially skipped, then landed in `embeddings-llm`** (Groq; template fallback without a key)
- Juliet / OWASP Benchmark / Big-Vul evaluation — still out of scope

## Target architecture (this PR)

Python package as **subpackages**. Shared DTOs live in `models/` (no I/O, no rules). Layers do not import `orchestrator`. `orchestrator` does not contain regexes. Retrieval does not instantiate the reasoner. Reasoner does not load the dataset from disk. Validator does not retrieve. Detector emits CWE *hints*; knowledge owns descriptions/mitigations. One `Evidence`, one `ReasoningResult`, one `binary_metrics`.

```text
src/cwe_vuln/
  __init__.py
  __main__.py                 # thin: A1 baseline CLI
  config.py                   # repo_root, Top-K, RRF k, LLM env names, SEED_CWE_IDS
  models/                     # DTOs only
    evidence.py
    retrieval.py
    reasoning.py
    pipeline.py               # CheckResult, ValidationReport, PipelineResult
    metrics.py                # BinaryMetrics + binary_metrics
  dataset/                    # SeedUnit + load_seed / split lists
  knowledge/                  # CWEKnowledgeBase
  sast/                       # regex rules + detect() + extract_evidence()
  retrieval/                  # TF-IDF index, RRF, HybridRetriever; no reasoner
  schema/                     # JSON Schema load + validate helpers
  reasoner/                   # TemplateReasoner.compose
  validator/                  # ResultValidator.check
  orchestrator/               # Pipeline + ports; SAST-first skip-LLM policy
  framework/                  # cwe-vuln-pipeline CLI
  cli/                        # baseline, knowledge, retrieval, schema, evidence entrypoints
```

Tests mirror packages:

```text
tests/dataset/  tests/knowledge/  tests/sast/  tests/retrieval/
tests/schema/   tests/reasoner/   tests/validator/  tests/orchestrator/
tests/framework/
```

`data/`, `docs/`, `results/`, `schemas/` stay outside `src/`. Java seeds stay in `data/seed/java/`.

Console scripts keep **command names**; module paths change:

| Command | New target |
| --- | --- |
| `cwe-vuln` / `cwe-vuln-eval` | `cwe_vuln.cli.baseline:main` |
| `cwe-vuln-kb` | `cwe_vuln.cli.knowledge:main` |
| `cwe-vuln-retrieve` | `cwe_vuln.cli.retrieval:main` |
| `cwe-vuln-schema` | `cwe_vuln.cli.schema:main` |
| `cwe-vuln-evidence` | `cwe_vuln.cli.evidence:main` |
| `cwe-vuln-pipeline` | `cwe_vuln.framework:main` |

Public imports: `from cwe_vuln.knowledge import CWEKnowledgeBase`, `from cwe_vuln.sast import detect, extract_evidence`, `from cwe_vuln.orchestrator import Pipeline`, etc.

## Data flow (unchanged behavior)

```text
SeedUnit
  → sast.extract_evidence → Evidence[]
  → retrieval.rank_for_unit → RankedHit[]     (TF-IDF + SAST + relationships, RRF, top_k)
  → reasoner.compose → ReasoningResult
  → validator.check → ValidationReport
  → framework metrics vs seed labels
```

Orchestrator path labels: `sast_first_skip_llm` when evidence exists and no key; `hybrid_retrieve_skip_llm` when no evidence and no key. On this snapshot the LLM path was skip-only. `embeddings-llm` later added `LLMReasoner` (Groq `GROQ_API_KEY`, default now `openai/gpt-oss-20b` after `llama-3.1-8b-instant` retired); no key still uses `TemplateReasoner`.

## Remaining research gaps (honest)

At the `modular-layout` snapshot, MiniLM and a live LLM client were still probes. **Both landed on `embeddings-llm`.** Public benchmarks and a full MITRE dump remain out of scope.

| Gap | Outcome |
| --- | --- |
| Dense MiniLM embeddings | **Initially skipped** in `modular-layout` to keep `uv sync` small. **Landed** on `embeddings-llm`: `all-MiniLM-L6-v2`, TF-IDF fallback (`embedder=tfidf_fallback`) if the model is missing. |
| Live LLM reasoner | **Initially skipped** (no client in the layout PR). **Landed** on `embeddings-llm`: Groq `LLMReasoner` (`GROQ_API_KEY`, default `openai/gpt-oss-20b`; `llama-3.1-8b-instant` retired on Groq free tier). No key → `TemplateReasoner` / skip-LLM. Invalid JSON → template fallback. `OPENAI_API_KEY` is unused. |
| Public benchmarks | Still out of scope. Do not invent Juliet/OWASP/Big-Vul numbers. |
| Full MITRE CWE dump | Still out of scope. Curated store stays. |

## Refinement (against the tree, 2026-09-17)

Checked `origin/main` @ `6afd6cb` (PR #9 merged), `results/*.json`, `pyproject.toml` scripts, and the working tree:

- Flat modules still present next to new packages (`dataset.py` *and* `dataset/`). That conflict must be resolved by **deleting** the sibling `.py` files after the package move — not by leaving shims.
- `retrieval/` currently has only `index.py` + `__init__.py` (the `__init__` already names `hybrid` and `rank`). Those two files are still to write; no extra phantom packages.
- No MiniLM extra was on that `main` (`jsonschema` + `pytest` only). `sentence-transformers` was **not** added in the layout PR: A3 already chose lexical TF-IDF to keep `uv sync` offline-small. Neural embeddings were initially skipped there, then landed on `embeddings-llm`.
- LLM env keys were not assumed present in the layout PR (no live client). Orchestrator skip-LLM policy stayed; Groq `LLMReasoner` landed later on `embeddings-llm`.
- Results files already exist; do not invent new scores. Re-running the pipeline may only refresh timestamps.
- DOCX on disk: `RAG_MultiAgent_Vulnerability_Thesis_Progress_Report.docx` (gitignored). Also write `Thesis Progress Report_RichaVerma_25MCSS02.docx` and allow that official filename in git.
- `research-papers/` untracked local copy: **out of this PR**.

## File-level work

**Add (layered packages)** — move existing logic, do not invent a parallel unused tree:

- `src/cwe_vuln/models/{evidence,retrieval,reasoning,pipeline,metrics}.py`
- `src/cwe_vuln/dataset/seed.py`
- `src/cwe_vuln/knowledge/store.py`
- `src/cwe_vuln/sast/{detector,extract}.py`
- `src/cwe_vuln/retrieval/{index,rank,hybrid}.py`
- `src/cwe_vuln/schema/contract.py`
- `src/cwe_vuln/reasoner/template.py`
- `src/cwe_vuln/validator/checks.py`
- `src/cwe_vuln/orchestrator/{ports,pipeline}.py`
- `src/cwe_vuln/framework/cli.py`
- `src/cwe_vuln/cli/{baseline,knowledge,retrieval,schema,evidence}.py`

**Delete after move** (no shims, no leftover flat dump):

- `src/cwe_vuln/{dataset,detector,evidence,knowledge,knowledge_cli,retrieval,retrieval_cli,schema,reasoner,validator,orchestrator,framework,evaluate,metrics,ports}.py`

Keep `config.py`, `__init__.py`, `__main__.py` at the package root.

**Tests:** move `tests/test_*.py` into mirrored folders; update imports (`cwe_vuln.detector` → `cwe_vuln.sast`, `cwe_vuln.metrics` → `cwe_vuln.models`, etc.).

**Docs (must match the new tree):**

- `docs/implementation-plan.md` (this file; update after execution)
- `docs/architecture.md` — real folders + mermaid
- `docs/advisor-phase-plan.md` — PRs 1–9 done; this PR = modular layout
- README, assignment/component docs that cite `src/cwe_vuln/foo.py`
- `rag-multiagent-context.txt` — future-session source of truth
- Progress report DOCX (existing `RAG_MultiAgent_Vulnerability_Thesis_Progress_Report.docx`, also save as `Thesis Progress Report_RichaVerma_25MCSS02.docx`)

**Do not** move Java seeds, commit secrets, or include `research-papers/` / `ApproachDoc.pdf`.

## Test plan

```bash
uv sync
uv run pytest
uv run cwe-vuln-pipeline
uv run cwe-vuln-pipeline --split all
uv run cwe-vuln
uv run cwe-vuln-kb demo
uv run cwe-vuln-retrieve --query "sql injection"
uv run cwe-vuln-schema data/schema_samples/vulnerable.json
uv run cwe-vuln-evidence --unit-id java_cwe89_sqli_concat
```

Pytest must stay green with the same seed assertions (12 units, 8/4, schema samples, hybrid ranks CWE-89 for the SQL concat query, pipeline SAST-first on vuln units). Re-running the pipeline may rewrite `results/framework-seed.json` timestamps; metrics must match the recorded seed-only scores.

## PR plan

1. `modular-layout` → `main`: layered packages, mirrored tests, console scripts, docs/context/DOCX. No new retrieval/LLM capability claims in that PR.
2. `embeddings-llm` → `main`: MiniLM neural embeddings + Groq `LLMReasoner` with offline fallback (replaces the earlier `thesis-completion` idea).

No `cursor/` branch prefix. No force-push.

## Executed (2026-09-17)

- Layered packages landed as planned. Flat `src/cwe_vuln/*.py` siblings deleted (no shims).
- Tests mirrored under `tests/{dataset,knowledge,sast,retrieval,schema,reasoner,validator,orchestrator,framework}/`.
- Console scripts point at `cwe_vuln.cli.*` and `cwe_vuln.framework:main`. Command names unchanged.
- `uv run pytest`: 35 passed.
- `uv run cwe-vuln-pipeline` and `--split all` match recorded seed-only metrics (test P/R/F1=1.0, paths 2/2 skip-LLM; all-12 paths 6/6).
- Neural embeddings: **initially skipped** in that PR (no `sentence-transformers`; TF-IDF remained lexical). **Then landed** on `embeddings-llm`.
- Live LLM: **initially skipped** in that PR (no client). **Then landed** on `embeddings-llm` as Groq `LLMReasoner` gated on `GROQ_API_KEY` / `CWE_VULN_LLM_API_KEY`.
- Second PR was opened as `embeddings-llm` (not `thesis-completion`) once MiniLM and Groq actually worked.
- Docs, `rag-multiagent-context.txt`, and progress-report DOCX updated to this tree.

## Embeddings + live LLM (branch `embeddings-llm`)

Layered tree is already on `main` (PR #10). This slice adds capability **without flattening** packages.

### Neural embeddings (`retrieval/`)

- `Embedder` protocol: `encode(texts) -> 2-D array-like`. Implementations: `MiniLMEmbedder` (`all-MiniLM-L6-v2`, project-local `.cache/`) and `TfidfEmbedder` (existing lexical path).
- `DenseIndex` cosine-ranks CWE documents. Unit tests use a tiny fake embedder; they must not download MiniLM.
- `HybridRetriever.hybrid_rank` fuses **neural cosine** with SAST CWE ids and one-hop relationships (RRF). Compare `neural` vs `lexical_tfidf` vs `hybrid_rrf` on `data/retrieval/labeled_queries.jsonl`.
- If MiniLM import/download fails: still importable; `embedder=tfidf_fallback` in results JSON; pipeline does not crash.
- Persist `results/assignment-3-retrieval.json` (+ md). Label **seed-only — not a benchmark**.

### Live LLM reasoner (`reasoner/`)

- Shared port: `Reasoner.reason(unit, evidence, hits) -> ReasoningResult`. `TemplateReasoner` stays the offline default. `LLMReasoner` is the same port.
- Key from env only: `GROQ_API_KEY` (primary) or `CWE_VULN_LLM_API_KEY` (override). Default model `openai/gpt-oss-20b` (Groq free-tier replacement after `llama-3.1-8b-instant` retired), default base URL `https://api.groq.com/openai/v1`. Optional `CWE_VULN_LLM_MODEL` (e.g. `openai/gpt-oss-120b`). Uses the OpenAI Python SDK OpenAI-compatible. Load project `.env` via python-dotenv; never commit it. `OPENAI_API_KEY` is not used.
- No key → orchestrator **does not construct** `LLMReasoner`; template path. Never raise at import for a missing key.
- Prompt asks for A4 JSON only (detection/explanation; no exploit generation). Parse, schema-validate; retry once; else template and `reasoner=llm_fallback_template`.
- Tests mock the SDK client. No live API in CI.

### Orchestrator policy (routing stays here)

Knobs in `config.py`: `use_llm_if_available`, `skip_llm_when_sast_hits`.

- Always SAST first.
- No key → `sast_first_skip_llm` / `hybrid_retrieve_skip_llm` + template (runs today).
- Key present and `use_llm_if_available` → `sast_then_llm` or `hybrid_retrieve_then_llm`, unless `skip_llm_when_sast_hits` and evidence exists.
- Log `path` (and reasoner/embedder) on every unit.

### Docs / verify / PR

README, architecture, advisor plan, retrieval/reasoner/orchestrator/framework, context file, progress-report DOCX. `uv run pytest` green without a key and without requiring MiniLM in unit tests. `uv run cwe-vuln-pipeline` offline. PR `embeddings-llm` → `main`.

## Executed (`embeddings-llm`, 2026-09-17)

- MiniLM `all-MiniLM-L6-v2` downloaded and used (`embedder=minilm`). Seed-only A3: neural R@1=0.9444 R@3=1.0 R@5=1.0 MRR=0.9722 vs lexical TF-IDF R@1=0.7778 R@3=0.9444 R@5=0.9444 MRR=0.8681. Hybrid RRF matches neural on this seed.
- `LLMReasoner` behind `Reasoner.reason`; no key today so orchestrator uses `TemplateReasoner`. Env: `GROQ_API_KEY`, optional `CWE_VULN_LLM_API_KEY`, optional `CWE_VULN_LLM_MODEL` / `CWE_VULN_LLM_BASE_URL`.
- `uv run pytest`: 48 passed with MiniLM cached (47 passed + 1 skipped when the model is absent).
- `uv run cwe-vuln-pipeline` offline: test split P=R=F1=1.0, paths 2/2 skip-LLM, reasoner=template, embedder=minilm.

## Executed (`research-eval`, 2026-09-17)

Research evaluation on an authored expanded corpus. Not Juliet / OWASP Benchmark / Big-Vul.

- Assignment 8/4 seed unchanged (`load_seed()` still 12). Research corpus 36 units; held-out `research_test` n=24 (12 FP + 12 FN traps).
- `cwe-vuln-eval --suite research` writes `results/experiments/` plus `results/research-eval-summary.json`.
- Detection (authored corpus — not a public benchmark): SAST/template P=R=F1=0.000 (12 FP / 12 FN); Groq `openai/gpt-oss-20b` then_llm P=0.857 R=1.000 F1=0.923 (2 FP / 0 FN); skip_llm P=0.500 R=1.000 F1=0.667.
- Retrieval 48 queries: hybrid R@1=0.854 MRR=0.917 vs MiniLM R@1=0.812 MRR=0.894 vs TF-IDF R@1=0.646 MRR=0.794. Hybrid still helps R@1/MRR.
- Explainability: then_llm validator 2/24 (SAST-tied contract); cited_lines 24/24 after normalize.
- Trial-and-error logged: FN javadoc tokens, FP javadoc rewrite regression, first LLM run invalidated for gold-label leakage in class names.
- `uv run pytest`: 54 passed. No `.env` / `gsk_` in git.

## Executed (`live-research`, 2026-09-17)

Live Groq is the default research path. Template/SAST remain ablations.

- `Pipeline.default()` / `cwe-vuln-pipeline` / `cwe-vuln-eval --suite research` require `GROQ_API_KEY`. Missing key exits non-zero. `--offline` and `--ablation template` keep the F1=0 contrast for the paper.
- Validator no longer requires `vulnerable` iff SAST evidence is non-empty. Checks: schema, CWE-in-KB, cited lines, JSON consistency. `sast_disagreement` is a warning.
- SAST stays evidence extraction. Decision is schema-validated Groq `LLMReasoner` grounded in code + evidence + hybrid CWE hits.
- Defendable contribution (not “100% novel” / not SOTA / not Juliet): RAG-augmented multi-agent detector for six Java CWEs on an authored 24-unit FP/FN trap split where regex/template fail and live LLM recovers most cases.
- `uv run pytest`: 62 passed (Groq mocked; default CLI tests fail clearly without a key).
- Live re-run: `uv run cwe-vuln-eval --suite research` + seed test n=4. then_llm P=0.857 R=1.000 F1=0.923, validator **24/24** (was 2/24). Seed test P=R=F1=1.000, validator 4/4. Metrics in `results/research-eval-summary.md`.
- No UAV/compiler code. No `.env` / `gsk_` in git.

## Executed (`benchmark-eval`, 2026-09-17)

Public Juliet Java v1.3 mapped-subset evaluation. Numbers from `cwe-vuln-eval`, not invented.

- NIST SARD zip HTTP 403; sparse-cloned `find-sec-bugs/juliet-test-suite` commit `b2c6df3733e2176fe7097e4784895c6891632b4c`.
- Ingested 20728 good/bad units from mapped/nearby folders. Missing Juliet folders: CWE-79, 22, 502, 798. Nearby ids not relabeled.
- Full regex SAST n=20728: P=0.300 R=0.334 F1=0.316.
- Stratified Groq sample n=72 (seed 13, 12 units × 6 CWE ids, `--per-cwe 12`): template F1=0.552; live `openai/gpt-oss-20b` F1=0.733 (P=0.917 R=0.611). No 429. 42/72 `llm_fallback_template`.
- Retrieval@Juliet skipped. OWASP Benchmark not run.
- `uv run pytest`: 66 passed. No `.env` / `gsk_` / Juliet tarball in git.
