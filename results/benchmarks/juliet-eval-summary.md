# Juliet Java evaluation summary

Juliet Java public-benchmark subset. Not the authored 36-unit research table. LLM scores are on a stratified sample only unless n equals the ingested SAST set. Nearby CWE folders keep their Juliet ids (no silent relabel to 79/22/798/327).

- Generated: `2026-09-17T13:34:15Z`
- Juliet version: `1.3`

| System | Status | Precision | Recall | F1 | FP | FN | n |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| template_juliet_sample | ok | 0.727 | 0.444 | 0.552 | 6 | 20 | 72 |
| llm_then_juliet_sample | ok | 0.917 | 0.611 | 0.733 | 2 | 14 | 72 |
| sast_regex_juliet | ok | 0.300 | 0.334 | 0.316 | 3736 | 3193 | 20728 |

## Trial log

- `template_juliet_sample` status=ok n=72
- `llm_then_juliet_sample` status=ok n=72
- `sast_regex_juliet` status=ok n=20728
