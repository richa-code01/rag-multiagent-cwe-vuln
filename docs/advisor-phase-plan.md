# Advisor phase plan

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

Canonical context: [`rag-multiagent-context.txt`](../rag-multiagent-context.txt)
How packages compose: [`architecture.md`](architecture.md)
Work executed this pass: [`implementation-plan.md`](implementation-plan.md)

Cost-aware routing is an orchestrator component. It is **not** in the thesis title.

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
| Validator | **Done** [PR #7](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/7) | `validator` | [validator.md](validator.md) | `uv run pytest tests/validator/test_validator.py` |
| Cost-aware orchestrator | **Done** [PR #8](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/8) | `orchestrator` | [orchestrator.md](orchestrator.md) | `uv run pytest tests/orchestrator/test_orchestrator.py` |
| Complete multi-agent framework | **Done** [PR #9](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/9) | `framework` | [framework.md](framework.md) | `uv run cwe-vuln-pipeline` → [results/framework-seed.json](../results/framework-seed.json) |
| Layered package layout | **Done** [PR #10](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/10) | `modular-layout` | [architecture.md](architecture.md) | `uv sync && uv run pytest && uv run cwe-vuln-pipeline` |
| Neural embeddings + LLM reasoner | **This PR** | `embeddings-llm` | [architecture.md](architecture.md) · [reasoning-agent.md](reasoning-agent.md) | MiniLM local; LLM via env key; template fallback |

## Honesty

- All detection/retrieval/framework scores are **seed-only — not a benchmark**
- A3 retrieval now has a MiniLM dense path; TF-IDF remains the lexical baseline and the offline fallback
- `TemplateReasoner` is the default offline composer; `LLMReasoner` runs only when `CWE_VULN_LLM_API_KEY` or `OPENAI_API_KEY` is set
