# Thesis evaluation summary

Sanitized prompts. Old public-suite LLM rows (gold-label leakage / silent Groq fallback) are retracted. Regex SAST on the six named corpora is kept. Fair SAST contrast is sast_regex_sanitized_*; sast_regex_* is raw disk.

- Generated: `2026-09-20T03:51:58Z`

| System | Status | Precision | Recall | F1 | FP | FN | n |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| llm_no_retrieval_research_test | ok | 0.857 | 1.000 | 0.923 | 2 | 0 | 24 |
| llm_no_sast_research_test | ok | 0.923 | 1.000 | 0.960 | 1 | 0 | 24 |
| llm_then_juliet_pairs | partial | 0.750 | 0.833 | 0.789 | 5 | 3 | 35 |
| llm_then_research_test | ok | 0.857 | 1.000 | 0.923 | 2 | 0 | 24 |
| sast_regex_juliet_pairs | ok | 0.615 | 0.444 | 0.516 | 5 | 10 | 36 |
| sast_regex_research_test | ok | 0.000 | 0.000 | 0.000 | 12 | 12 | 24 |
| sast_regex_sanitized_juliet_pairs | ok | 0.615 | 0.444 | 0.516 | 5 | 10 | 36 |
| sast_regex_sanitized_research_test | ok | 0.000 | 0.000 | 0.000 | 6 | 12 | 24 |
| sast_regex_vul4j_sliced | ok | 0.500 | 0.167 | 0.250 | 2 | 10 | 24 |
| template_juliet_pairs | ok | 0.615 | 0.444 | 0.516 | 5 | 10 | 36 |
| template_research_test | ok | 0.000 | 0.000 | 0.000 | 6 | 12 | 24 |

## Trial log

- `llm_no_retrieval_juliet_pairs` status=skipped n=None
- `llm_no_retrieval_research_test` status=ok n=24
- `llm_no_sast_research_test` status=ok n=24
- `llm_then_juliet_pairs` status=partial n=35 error=juliet_s04_CWE89_SQL_Injection__URLConnection_prepareStatement_14__method_goodG2B1: Error code: 429 - {'error': {'message': 'Rate limit reached for model `openai/gpt-oss-20b` in organization `org_01kkjxq033ean84gxkg2vn4bxn` service tier `on_demand` on tokens per day (TPD): Limit 200000, Used 197791, Requested 3390. Please try again in 8m30.191999999s. Need more tokens? Upgrade to Dev Tier today at https://console.groq.com/settings/billing', 'type': 'tokens', 'code': 'rate_limit_exceeded'}} pair_acc=0.5294117647058824
- `llm_then_research_test` status=ok n=24
- `llm_then_vul4j_sliced` status=skipped n=None
- `retrieval_units_juliet_pairs` status=ok n=None
- `retrieval_units_research_test` status=ok n=None resumed
- `sast_regex_juliet_pairs` status=ok n=36
- `sast_regex_research_test` status=ok n=24 resumed
- `sast_regex_sanitized_juliet_pairs` status=ok n=36
- `sast_regex_sanitized_research_test` status=ok n=24 resumed
- `sast_regex_vul4j_sliced` status=ok n=24 resumed
- `semgrep_juliet_pairs` status=skipped n=None
- `template_juliet_pairs` status=ok n=36
- `template_research_test` status=ok n=24 resumed
