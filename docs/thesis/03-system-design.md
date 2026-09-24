# Chapter 3 — System design

Implemented as the `cwe-vuln` src-layout package. Production-grade HLD/LLD: [`../design/hld.md`](../design/hld.md), [`../design/lld.md`](../design/lld.md).

## Honesty about SAST

Six pedagogical regexes (SQL concat, unencoded HTML concat, `new File(...+)`, `ObjectInputStream`/`readObject`, hardcoded secret literals, `getInstance("MD5|DES|…")`). Not AST, not taint, not CodeQL. Fair tables score regex on the **same sanitized units** the LLM sees (`sast_regex_sanitized_*`). Raw-disk regex is a separate row.

## RAG

Passages are `{CWE-id}::main|mitigations|detection` from the MITRE subset. Hybrid rank: MiniLM cosine (TF-IDF fallback) + SAST ids + one-hop relationships, RRF (`k=60`), `top_k=5`. Query = evidence/sink window (`retrieval_query_text`), never gold `notes`, never the file head. Hits carry `passage` text into the prompt.

## LLM

`ChatProvider` port; Groq default. Temperature 0, JSON mode. Invalid JSON retried once then `llm_fallback_template` **with** `fallback_reason`. HTTP 429 is re-raised (never silent template-as-Groq). Prompts are sanitized (opaque id, comments blanked, `bad`/`good` renamed). Cited lines are **not** rewritten when the snippet is wrong. CWE ids outside the KB (including `CWE-0`) are clamped to the top retrieval hit; `cwe_clamped_from` is recorded.

## Agents and routing

Named agents are staged specialists (evidence → retrieval → reason → validate) under a deterministic orchestrator. The default path is always-LLM. `skip_llm_when_sast_hits` is an opt-in ablation. `final_confidence` is a logged heuristic, **not** a routing gate.

## Confidence

`final_confidence = 0.45·llm + 0.25·retrieval + 0.20·sast_agreement + 0.10·validator`. Documented heuristic, not a calibrated probability, not a gate.
