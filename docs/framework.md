# Complete framework

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

Thin CLI over `Pipeline.run` (`src/cwe_vuln/framework/`). Agents and data flow: [`architecture.md`](architecture.md).

```text
Java unit
  → SAST Evidence[]          (regex rules; evidence only)
  → RankedHit[]              (hybrid MiniLM or TF-IDF fallback + SAST + CWE relationships)
  → ReasoningResult          (Groq LLMReasoner; A4 schema)
  → ValidationReport         (schema / KB / cited lines / JSON consistency)
  → binary metrics vs seed labels
```

Default evaluation is the **4 test units**. Pass `--split all` for all 12. **seed-only — not a benchmark.**

```bash
uv run cwe-vuln-pipeline                 # requires GROQ_API_KEY
uv run cwe-vuln-pipeline --split all
uv run cwe-vuln-pipeline --offline       # TemplateReasoner ablation
```

Writes `results/framework-seed.json` (and `.md`). Missing Groq key → exit 1 with a message to set `GROQ_API_KEY`. Recorded test-split run (**seed-only**, live Groq `openai/gpt-oss-20b`, embedder=`minilm`): P=1.000 R=1.000 F1=1.000 FP=0 FN=0, paths `sast_then_llm=2` / `hybrid_retrieve_then_llm=2`, reasoner `llm`.

Still not a public benchmark. MiniLM is local. Live Groq uses `GROQ_API_KEY`. Template/SAST are ablations (`--offline`, `cwe-vuln-eval --ablation template`); they scored F1=0 on the 24-unit research split.

Research evaluation (authored 24-unit held-out split) is `uv run cwe-vuln-eval --suite research` → [`research-evaluation.md`](research-evaluation.md).
