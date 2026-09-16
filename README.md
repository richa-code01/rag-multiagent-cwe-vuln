# RAG-Augmented Multi-Agent CWE Detector (seed slice)

Offline Python slice for [richa-code01/rag-multiagent-cwe-vuln](https://github.com/richa-code01/rag-multiagent-cwe-vuln): lexical CWE retrieval plus three deterministic agents (Code Analyzer, CWE Specialist, Reporter).

This is Assignment 1 only. It does not download Big-Vul, call an LLM API, or report a literature benchmark.

## Seed-only metrics

`uv run cwe-rag eval` prints precision, recall, and F1 of **1.0** on eight hand-written snippets in `src/cwe_rag/seed_cases.py`. That score is **seed-only**. It is not a Juliet, Big-Vul, or paper-table result.

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev
uv run pytest
```

## Usage

```bash
uv run cwe-rag eval
uv run cwe-rag detect --file examples/sqli_concat.py
uv run cwe-rag detect --code "el.innerHTML = req.query.comment"
```

## Layout

| Path | Role |
| --- | --- |
| `src/cwe_rag/` | Seed knowledge, retriever, agents, eval, CLI |
| `tests/` | Retrieval, pipeline labels, seed P/R/F1, CLI |
| `ResearchPapers/` | Existing thesis PDFs (unchanged) |
| `Overview.md` | Original system-overview notes (unchanged) |

Later assignments (corpus RAG, LLM agents, published benchmarks) are out of scope here.
