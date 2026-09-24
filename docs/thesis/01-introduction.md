# Chapter 1 — Introduction

**Thesis:** RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases

Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

Source of numbers: `results/thesis/*.json` generated `2026-09-20T03:51:58Z`. Do not mix these tables with retracted 2026-09-17 public-suite LLM rows.

## Problem

Explainable vulnerability detection on Java units: decide `vulnerable` / `not_vulnerable` / `uncertain`, name a CWE, cite source lines, and state root cause, explanation, and remediation. Regex SAST is **evidence**, not the decision. The knowledge base is a parsed MITRE CWE XML **subset** (catalog v4.20 in `data/cwe/knowledge.json`), not the full catalog.

## Claim (defendable)

Related work already uses RAG and multi-agent detection on C/C++, Python, or RTL. This thesis claims a **specific composition** for Java and six web/enterprise CWE families: regex evidence + hybrid MiniLM/TF-IDF + CWE-relationship RRF + schema-bound LLM + a **deterministic** validator. Agents are **staged specialists** under a deterministic orchestrator, not a conversation bus. The default path is **always-LLM**; fused confidence is **logged, not gating**. It does **not** claim SOTA or “first RAG-CWE detector.”

The public LLM number is **C2 Juliet pair accuracy** (with bootstrap CI). C1 authored-trap F1 is a valid “regex fails, LLM recovers” contrast only, and is trap-overfit by construction.

## Six ApproachDoc stages

1. EvidenceAgent — regex SAST spans
2. KnowledgeAgent — hybrid CWE RAG (query = evidence/sink window, never gold notes, never file head)
3. Orchestrator — route log; risk / retrieval confidence / coverage / fused confidence are **logged**, not used to skip the LLM
4. ReasoningAgent — Groq `openai/gpt-oss-20b` JSON (provider-swappable); unknown CWE ids clamped to retrieved hits
5. ValidatorAgent — schema / CWE-in-KB / cited lines (raw + indent-normalized) / consistency; SAST disagreement is a warning
6. Report — `PipelineResult` diagnostics + signals

Design of record: [`docs/design/hld.md`](../design/hld.md) · [`docs/design/lld.md`](../design/lld.md).
