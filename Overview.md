# System Overview

The current advisor sequence and implementation status live in [`docs/advisor-phase-plan.md`](docs/advisor-phase-plan.md). Canonical context: [`rag-multiagent-context.txt`](rag-multiagent-context.txt). **Assignments 1–4, the wired seed pipeline, MiniLM neural embeddings, and a Groq LLM reasoner are implemented.** Retrieval uses `sentence-transformers` `all-MiniLM-L6-v2`, with TF-IDF fallback if the model is missing (`embedder=tfidf_fallback`). The default live path requires Groq (`GROQ_API_KEY`, default `openai/gpt-oss-20b` at `https://api.groq.com/openai/v1`); `OPENAI_API_KEY` is unused. Missing key → CLI exits non-zero. `TemplateReasoner` is `--offline` / `--ablation template` only. Evaluation is **seed-only** for the assignment split and **authored-corpus** for the 24-unit research split (not a public benchmark). The notes below are a high-level product sketch.

This project proposes a multi-agent AI system for detecting security bugs in code. The goal is not only to identify vulnerabilities, but also to explain why a code pattern is risky using domain knowledge from security standards.

To support explainable vulnerability detection, the system will use **Retrieval-Augmented Generation (RAG)** to retrieve relevant facts from the **Common Weakness Enumeration (CWE)** database. By grounding each analysis in CWE references, the agents can produce outputs that are more transparent, traceable, and useful in practice.

## Project Phases

### Phase 1: Knowledge Mapping

Study the CWE database and review existing RAG-based architectures to understand how security knowledge can be retrieved and applied during analysis.

### Phase 2: Agent Design

Define specialized roles for the collaborating agents, such as a **Code Analyzer**, a **CWE Specialist**, and a **Reporter**.

### Phase 3: RAG Implementation

Build a vector database of CWE entries so the agents can retrieve relevant facts in real time during vulnerability analysis.

### Phase 4: Prototyping

Use an orchestration framework such as **LangChain** or **AutoGen** to connect the agents and coordinate the workflow.

### Phase 5: Evaluation

Test the system against known vulnerable code snippets to measure how well it detects security bugs and how clearly it explains them.

## Expected Outcome

The final system should combine multi-agent reasoning with security knowledge retrieval to produce explainable and standards-based vulnerability detection results.
