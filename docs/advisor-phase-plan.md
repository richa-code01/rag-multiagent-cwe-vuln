# Advisor phase plan

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

This is the working sequence. Only Assignment 1 is in this PR.

## Assignments 1–4

| # | Assignment | Status in this PR |
| --- | --- | --- |
| 1 | Dataset + baseline (Java CWE seed, 8/4 split, regex/SAST-style detector, precision/recall/F1) | **This PR** — seed and baseline complete; thesis evaluation is not. |
| 2 | CWE knowledge layer (ingest/structure CWE text for later retrieval) | **Not started** |
| 3 | Hybrid retrieval over that knowledge layer | **Not started** |
| 4 | Structured reasoning output schema | **Not started** |

## After Assignment 4 (not started)

1. SAST evidence extraction as a product stage
2. Reasoning agent
3. Validator agent
4. Cost-aware orchestrator
5. Full multi-agent framework wired end-to-end

Cost-aware routing is later work. It is not in the thesis title and is not part of Assignment 1.

## What this PR must not be read as

- Not a CWE knowledge-base product
- Not RAG / hybrid retrieval
- Not multi-agent orchestration
- Not a completed evaluation of the thesis system
- Not public-benchmark results
