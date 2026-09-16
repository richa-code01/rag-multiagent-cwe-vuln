# Complete framework

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

Thin CLI over `Pipeline.run` (`src/cwe_vuln/framework/`). Agents and data flow: [`architecture.md`](architecture.md).

```text
Java unit
  → SAST Evidence[]          (regex rules)
  → RankedHit[]              (hybrid MiniLM or TF-IDF fallback + SAST + CWE relationships)
  → ReasoningResult          (template, or LLM when a key is set; A4 schema)
  → ValidationReport
  → binary metrics vs seed labels
```

Default evaluation is the **4 test units**. Pass `--split all` for all 12. **seed-only — not a benchmark.**

```bash
uv run cwe-vuln-pipeline
uv run cwe-vuln-pipeline --split all
```

Writes `results/framework-seed.json` (and `.md`). Recorded test-split run (no API key, embedder=`minilm`): P=1.000 R=1.000 F1=1.000 FP=0 FN=0, 4/4 validator pass, paths `sast_first_skip_llm=2` / `hybrid_retrieve_skip_llm=2`, reasoner `template`.

Still not a public benchmark. MiniLM is local. Live LLM waits on `OPENAI_API_KEY`; without a key the pipeline stays offline.
