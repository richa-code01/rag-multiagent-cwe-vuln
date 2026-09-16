# Advisor phase plan

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

Canonical context dump (keep in sync with this file): [`rag-multiagent-context.txt`](../rag-multiagent-context.txt)

Cost-aware routing is later work. It is **not** in the thesis title.

## Assignments 1–4

| # | Assignment | Status | Doc | Results / how to run |
| --- | --- | --- | --- | --- |
| 1 | Dataset + baseline (12 Java units, 8/4 split, regex detector, P/R/F1) | **Done** — merged [PR #1](https://github.com/richa-code01/rag-multiagent-cwe-vuln/pull/1) | [assignment-1-dataset-baseline.md](assignment-1-dataset-baseline.md) | [results/assignment-1-baseline.json](../results/assignment-1-baseline.json) — `uv run cwe-vuln` |
| 2 | CWE knowledge layer (JSON store + query API) | **This PR** | [assignment-2-cwe-knowledge.md](assignment-2-cwe-knowledge.md) | `uv run cwe-vuln-kb demo` (no retrieval metrics; that is Assignment 3) |
| 3 | Hybrid retrieval | **Not started** | — | — |
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
- No claim that thesis evaluation is complete
- Assignment 1 scores are **seed-only — not a benchmark**
- Assignment 2 is a curated CWE subset, not an official MITRE dump
