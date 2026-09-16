# Advisor phase plan

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

Canonical context: [`rag-multiagent-context.txt`](../rag-multiagent-context.txt)
How packages compose: [`architecture.md`](architecture.md)

Cost-aware routing is later work. It is **not** in the thesis title.

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
| Reasoning agent | **Done** [PR #6](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/6) | `reasoning-agent` | [reasoning-agent.md](reasoning-agent.md) | `uv run pytest tests/test_reasoner.py` |
| Validator | **This PR** | `validator` | [validator.md](validator.md) | `uv run pytest tests/test_validator.py` |
| Cost-aware orchestrator | Not started | `orchestrator` | — | — |
| Complete multi-agent framework | Not started | `framework` | — | — |

## Honesty

- A1 detection and A3 retrieval scores are **seed-only — not a benchmark**
- A3 retrieval is lexical TF-IDF, not neural embeddings
- Reasoner is a template composer on the seed, not an LLM agent
