# Operator runbook

The console is a local view over the same functions the CLI calls. It is not a multi-tenant service.

```bash
uv sync
cp .env.example .env   # set GROQ_API_KEY for the live path; never commit it
uv run cwe-vuln-ui
```

Open `http://127.0.0.1:8765`. The process refuses any host other than localhost.

## What each control runs

| Control | Command |
| --- | --- |
| Seed pipeline, split test, offline | `uv run cwe-vuln-pipeline --split test --offline` |
| Evaluation suite | `uv run cwe-vuln-eval --suite <name>` |
| Template ablation | add `--offline` |
| Resume a thesis run under the token cap | `uv run cwe-vuln-eval --suite thesis --resume --max-tokens 200000` |
| C7 model ablation | add `--include-model-ablation` |

The Run panel prints that command before the job starts. One job runs at a time. Cancel stops between units, not in the middle of an HTTP call to the provider. A missing provider key fails the live path the same way the CLI exits. Offline template runs do not need a key.

Provider and model come from the environment (`CWE_VULN_LLM_PROVIDER`, `CWE_VULN_LLM_MODEL`, and the provider key). The page shows whether a key is configured. It does not display the key.

## Status

C1–C8 cards are read from `results/thesis/summary.json`. `partial` and `skipped` stay as written. Public-suite LLM numbers from 2026-09-17 stay retracted. Regex SAST on the six suites is kept.

## Remaining experiments

Do not type scores in by hand. A new run writes a new trial file.

1. **C2.** `uv run cwe-vuln-eval --suite thesis --resume --max-tokens 200000` scores the Juliet unit that the token cap cut off, then recomputes pair accuracy and the bootstrap CI.
2. **C4 on Juliet.** The same command is what writes `llm_no_retrieval_juliet_pairs`. Until that file exists, do not claim RAG helps on Juliet. On the authored traps, no-retrieval F1 already matches the full path.
3. **C3 sliced Vul4J.** Same resume command. If the daily budget is gone, leave the row skipped.
4. **C7.** Add `--include-model-ablation` only when tokens remain.
5. **C8.** Use the Spot-check panel. Empty labels stay `not_run`. A complete form is a single rater's labels, not an inter-rater study and not a detection metric.

Retrieval recall on the Juliet pair sample (hybrid R@1 0.25) is a follow-on experiment. Changing the query window is a new ablation and a new result file, not a silent edit of the default path.

## Benchmarks

The six scored slices are in `data/benchmarks/` at the commits in [`data/benchmarks/NOTICES.md`](../data/benchmarks/NOTICES.md). Re-download with `uv run python scripts/vendor_benchmarks.py` only if a tree is missing. Do not commit `data/benchmarks/downloads/` or zip files.
