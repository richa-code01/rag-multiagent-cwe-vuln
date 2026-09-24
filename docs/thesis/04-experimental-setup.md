# Chapter 4 — Experimental setup

Repro: `uv run pytest` (no live LLM) then `uv run cwe-vuln-eval --suite thesis --resume --max-tokens 200000` with `GROQ_API_KEY`. Groq free-tier observed cap **200,000 tokens/day** and **8,000 tokens/minute**. Model: `openai/gpt-oss-20b` (verified live 2026-09-18). Fallbacks `openai/gpt-oss-120b` and `qwen/qwen3.8-27b` were **not** run (C7 skip).

| Slice | n | Metric |
| --- | ---: | --- |
| C1 authored research_test | 24 | Binary P/R/F1 (abstain-as-negative **and** exclude-abstain), CWE exact / parent-child / peer, tokens |
| C2 Juliet pairs | 18 pairs / 36 units (3 per family, seed=13), **single-file variants only** | Pair accuracy + bootstrap 95% CI; binary F1 |
| C3 Vul4J sliced ±40 | planned 24; LLM may be partial (TPD) | Do not cite a partial row as a real-world claim |
| C4 | template + raw/sanitized SAST; no-RAG/no-SAST LLM if TPD allows | Required before claiming RAG/SAST help |
| C5 Semgrep | skip unless installed | Not compared to CodeQL |
| C8 human spot-check | `not_run` | Awaits Richa; 30 unit ids sampled, labels empty |

Pair definition: correct iff `bad → vulnerable` **and** matched `good* → not_vulnerable`. `uncertain` is pair-incorrect and is reported as an abstention rate. CWE-502 is not present in Juliet Java 1.3.

Juliet `_NNa/_NNb` flow variants are **excluded** from the pair pool (the `a` file often only forwards data to a `b` helper that holds the sink). Nearby folder ids (80, 23, 259, 328) keep their Juliet numbers and are not relabeled to 79/22/798.

Public-suite **regex SAST** (full ingested sets, 2026-09-17) is kept. Public-suite **LLM** rows from that date are retracted (gold leakage / silent fallback).
