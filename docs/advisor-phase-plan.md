# Advisor phase plan

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

Canonical context dump: [`rag-multiagent-context.txt`](../rag-multiagent-context.txt)

Cost-aware routing is later work. It is **not** in the thesis title.

## Assignments 1–4

| # | Assignment | Status | Doc | Results / how to run |
| --- | --- | --- | --- | --- |
| 1 | Dataset + baseline (12 Java units, 8/4 split, regex detector, P/R/F1) | **Done** — [PR #1](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/1) | [assignment-1-dataset-baseline.md](assignment-1-dataset-baseline.md) | [results/assignment-1-baseline.json](../results/assignment-1-baseline.json) — `uv run cwe-vuln` |
| 2 | CWE knowledge layer (JSON store + query API) | **Done** — [PR #2](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/2) | [assignment-2-cwe-knowledge.md](assignment-2-cwe-knowledge.md) | `uv run cwe-vuln-kb demo` |
| 3 | Hybrid retrieval (TF-IDF + SAST + CWE relationships, RRF) | **This PR** | [assignment-3-hybrid-retrieval.md](assignment-3-hybrid-retrieval.md) | [results/assignment-3-retrieval.json](../results/assignment-3-retrieval.json) — `uv run cwe-vuln-retrieve` |
| 4 | Structured reasoning output schema | **Not started** | — | — |

## After Assignment 4 (not started)

| Component | Status | Intended branch |
| --- | --- | --- |
| SAST evidence extraction | Not started | `sast-evidence` |
| Reasoning agent | Not started | `reasoning-agent` |
| Validator | Not started | `validator` |
| Cost-aware orchestrator | Not started | `orchestrator` |
| Complete multi-agent framework | Not started | `framework` |

## Honesty

- No public-benchmark numbers
- Assignment 1 detection scores and Assignment 3 retrieval scores are **seed-only — not a benchmark**
- Assignment 3 “semantic” retrieval is lexical TF-IDF, not neural embeddings
- No claim that thesis evaluation is complete
