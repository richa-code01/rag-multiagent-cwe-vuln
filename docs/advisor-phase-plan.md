# Advisor phase plan

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

Canonical context: [`rag-multiagent-context.txt`](../rag-multiagent-context.txt)
How packages compose: [`architecture.md`](architecture.md)
Production-grade design: [`design/hld.md`](design/hld.md) · [`design/lld.md`](design/lld.md)
Work executed this pass: [`implementation-plan.md`](implementation-plan.md)

Cost-aware routing is an orchestrator component. It is **not** in the thesis title.

## Contribution (defendable)

A RAG-augmented multi-agent detector for six Java CWEs: SAST emits evidence, hybrid MiniLM + relationship/RRF retrieves CWE knowledge, Groq writes A4-schema explanations, and the validator checks schema/lines/KB — not SAST agreement. Agents are staged specialists; the default path is always-LLM; confidence is logged, not gating. On an authored 24-unit FP/FN trap split, regex and template fail; live LLM recovers most cases (trap contrast only). The public LLM number is C2 pair accuracy with a CI.

Do **not** tell the advisor this is SOTA, Juliet/OWASP numbers, 100% novel, or the first RAG-CWE detector. Related work already combines retrieval, agents, and CWE catalogs. The claim is this specific composition plus an honest trap-split evaluation.

## Assignments 1–4

| # | Assignment | Status | Doc | How to run |
| --- | --- | --- | --- | --- |
| 1 | Dataset + baseline | **Done** [PR #1](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/1) | [assignment-1-dataset-baseline.md](assignment-1-dataset-baseline.md) | `uv run cwe-vuln` |
| 2 | CWE knowledge layer | **Done** [PR #2](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/2) | [assignment-2-cwe-knowledge.md](assignment-2-cwe-knowledge.md) | `uv run cwe-vuln-kb demo` |
| 3 | Hybrid retrieval | **Done** [PR #3](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/3) | [assignment-3-hybrid-retrieval.md](assignment-3-hybrid-retrieval.md) | `uv run cwe-vuln-retrieve` |
| 4 | Structured reasoning output schema | **Done** [PR #4](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/4) | [assignment-4-output-schema.md](assignment-4-output-schema.md) | `uv run cwe-vuln-schema data/schema_samples/vulnerable.json` |

## After Assignment 4

| Component | Status | Branch | Doc | How to run |
| --- | --- | --- | --- | --- |
| SAST evidence extraction | **Done** [PR #5](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/5) | `sast-evidence` | [sast-evidence.md](sast-evidence.md) | `uv run cwe-vuln-evidence --unit-id java_cwe89_sqli_concat` |
| Reasoning agent | **Done** [PR #6](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/6) | `reasoning-agent` | [reasoning-agent.md](reasoning-agent.md) | `uv run pytest tests/reasoner/test_reasoner.py` |
| Validator | **Done** [PR #7](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/7); SAST-iff-vulnerable **removed** | `live-research` | [validator.md](validator.md) | `uv run pytest tests/validator/test_validator.py` |
| Cost-aware orchestrator | **Done** [PR #8](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/8); default is always-LLM; confidence logged not gating | `live-research` | [orchestrator.md](orchestrator.md) | `uv run pytest tests/orchestrator/test_orchestrator.py` |
| Complete multi-agent framework | **Done** [PR #9](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/9) | `framework` | [framework.md](framework.md) | `uv run cwe-vuln-pipeline` → [results/framework-seed.json](../results/framework-seed.json) |
| Layered package layout | **Done** [PR #10](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/10) | `modular-layout` | [architecture.md](architecture.md) | `uv sync && uv run pytest && uv run cwe-vuln-pipeline` |
| Neural embeddings + LLM reasoner | **Done** | `embeddings-llm` | [architecture.md](architecture.md) · [reasoning-agent.md](reasoning-agent.md) | MiniLM local; Groq required on default path |
| Research evaluation (authored corpus) | **Done** | `research-eval` | [research-evaluation.md](research-evaluation.md) | `uv run cwe-vuln-eval --suite research` |
| Live research default | **Done** | `live-research` | [research-evaluation.md](research-evaluation.md) | Requires `GROQ_API_KEY`; `--ablation template` for F1=0 contrast |
| Juliet Java v1.3 mapped eval | **Done** | `benchmark-eval` | [benchmark-plan.md](benchmark-plan.md) · [benchmark-results.md](benchmark-results.md) | `uv run cwe-vuln-eval --suite juliet` |
| Six public Java suites | **Done** (SAST kept; LLM rows retracted) | `six-benchmarks` | [six-benchmark-results.md](six-benchmark-results.md) | `uv run cwe-vuln-eval --suite all-sast` |
| Sanitized thesis eval | **Done** (C2 partial TPD 35/36; C4-on-C1 ran; C3/C4-on-C2 skipped TPD) | `thesis-complete` | [thesis/05-results.md](thesis/05-results.md) · [thesis/08-error-analysis.md](thesis/08-error-analysis.md) | `uv run cwe-vuln-eval --suite thesis --resume --max-tokens 200000` |
| HLD / LLD | **Done** | `thesis-complete` | [design/hld.md](design/hld.md) · [design/lld.md](design/lld.md) | — |

## Honesty

- Assignment 1–4 and seed pipeline scores remain **seed-only — not a benchmark** (12 units / 18 queries)
- Research evaluation is on an **authored expanded corpus** (36 units, 24 held-out traps, 48 queries) — **not** the Juliet table
- Juliet Java v1.3 mapped subset SAST n=20728 F1=0.316 is kept. The n=72 Groq F1=0.733 row is **retracted**. Replacement: rebuilt single-file pair sample, pair accuracy **9/17 = 0.529** (CI [0.294, 0.765]) on complete pairs; n_scored=35/36 TPD; binary F1=0.789 ([thesis/05-results.md](thesis/05-results.md)). First C2 sample included multi-file `_NNa` variants and is archived; later pair pools exclude them.
- A3 retrieval has a MiniLM dense path; TF-IDF remains the lexical baseline and the offline fallback
- A3 retrieval has a MiniLM dense path; TF-IDF remains the lexical baseline and the offline fallback
- `LLMReasoner` is the default live composer; `TemplateReasoner` is `--offline` / `--ablation template` only
- SAST and template F1=0 on research_test is the **contrast**, not the deployed system
- Trial-and-error kept: label leak, javadoc regex, retired `llama-3.1-8b-instant`
