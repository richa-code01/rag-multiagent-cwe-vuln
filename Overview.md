# System overview

RAG-augmented multi-agent detector for explainable Java vulnerability analysis. A deterministic orchestrator runs specialist stages: regex SAST evidence, hybrid CWE retrieval, a schema-bound LLM explanation, and a validator. This is not a LangChain or AutoGen chat, and it is not a production SAST engine.

Student: Richa Verma (25MCSS02). Advisor: Dr. Akshay Pandey.

## What runs

```text
Java unit
  → EvidenceAgent (regex spans, not the decision)
  → KnowledgeAgent (MiniLM + TF-IDF + SAST ids + CWE relationships, RRF)
  → ReasoningAgent (Groq by default; template is an ablation)
  → ValidatorAgent (schema, CWE-in-KB, cited lines, consistency)
  → metrics
```

Open the operator console:

```bash
uv sync
uv run cwe-vuln-ui
```

That serves `http://127.0.0.1:8765` and only binds to localhost. From there you pick a suite, ablation, and token budget, inspect one unit, search the CWE store, and fill C8 labels. The same commands still work:

```bash
uv run cwe-vuln-pipeline
uv run cwe-vuln-eval --suite thesis --resume --max-tokens 200000
```

## Where to read

- Architecture: [`docs/architecture.md`](docs/architecture.md)
- Design: [`docs/design/hld.md`](docs/design/hld.md) and [`docs/design/lld.md`](docs/design/lld.md)
- How to run and what is still unfinished: [`docs/operator.md`](docs/operator.md)
- Thesis chapters: [`docs/thesis/README.md`](docs/thesis/README.md)
- Benchmark slices: [`data/benchmarks/NOTICES.md`](data/benchmarks/NOTICES.md)

Related-work PDFs live in [`research-papers/`](research-papers/). `ResearchPapers/` is an older copy; `RP1Understanding.md` is not identical, so both stay.

Authored 36-unit scores and Juliet scores are different tables. Public-suite LLM rows from 2026-09-17 stay retracted. Do not claim that RAG helps on Juliet until `llm_no_retrieval_juliet_pairs` exists.
