# Six-suite evaluation summary

Public/industry-style Java suite. Regex SAST is not CodeQL. LLM scores are on a deterministic stratified sample, not the full ingested set. Six-suite measurement does not prove 100% novelty; the claim is this method (SAST evidence + hybrid CWE retrieval + schema-bound Groq) vs these corpora/baselines.

- Generated: `2026-09-17T14:08:18Z`

| System | Suite | Status | Precision | Recall | F1 | FP | FN | n |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| llm_then_cvefixes_java_slice_sample | cvefixes-java-slice-llm-sample | ok | 0.000 | 0.000 | 0.000 | 1 | 5 | 12 |
| llm_then_find_sec_bugs_sample | find-sec-bugs-llm-sample | ok | 0.500 | 0.286 | 0.364 | 2 | 5 | 12 |
| llm_then_juliet_sample | juliet-llm-sample | ok | 0.917 | 0.611 | 0.733 | 2 | 14 | 72 |
| llm_then_owasp_benchmark_sample | owasp-benchmark-llm-sample | ok | 1.000 | 0.167 | 0.286 | 0 | 5 | 12 |
| llm_then_securibench_micro_sample | securibench-micro-llm-sample | ok | 0.750 | 0.375 | 0.500 | 1 | 5 | 12 |
| llm_then_vul4j_sample | vul4j-llm-sample | ok | 0.000 | 0.000 | 0.000 | 1 | 6 | 12 |
| sast_regex_cvefixes_java_slice | cvefixes-java-slice | ok | 0.500 | 0.130 | 0.207 | 6 | 40 | 92 |
| sast_regex_find_sec_bugs | find-sec-bugs | ok | 0.833 | 0.294 | 0.435 | 4 | 48 | 79 |
| sast_regex_juliet | juliet-sast | ok | 0.300 | 0.334 | 0.316 | 3736 | 3193 | 20728 |
| sast_regex_owasp_benchmark | owasp-benchmark | ok | 0.660 | 0.282 | 0.395 | 206 | 1016 | 2740 |
| sast_regex_securibench_micro | securibench-micro | ok | 0.667 | 0.038 | 0.072 | 2 | 101 | 119 |
| sast_regex_vul4j | vul4j | ok | 0.500 | 0.161 | 0.244 | 5 | 26 | 62 |
| template_cvefixes_java_slice_sample | cvefixes-java-slice-llm-sample | ok | 0.000 | 0.000 | 0.000 | 1 | 5 | 12 |
| template_find_sec_bugs_sample | find-sec-bugs-llm-sample | ok | 0.500 | 0.286 | 0.364 | 2 | 5 | 12 |
| template_juliet_sample | juliet-llm-sample | ok | 0.727 | 0.444 | 0.552 | 6 | 20 | 72 |
| template_owasp_benchmark_sample | owasp-benchmark-llm-sample | ok | 1.000 | 0.167 | 0.286 | 0 | 5 | 12 |
| template_securibench_micro_sample | securibench-micro-llm-sample | ok | 0.750 | 0.375 | 0.500 | 1 | 5 | 12 |
| template_vul4j_sample | vul4j-llm-sample | ok | 0.000 | 0.000 | 0.000 | 1 | 6 | 12 |

## Trial log

- `llm_then_cvefixes_java_slice_sample` suite=cvefixes-java-slice-llm-sample status=ok n=12
- `llm_then_find_sec_bugs_sample` suite=find-sec-bugs-llm-sample status=ok n=12
- `llm_then_juliet_sample` suite=juliet-llm-sample status=ok n=72
- `llm_then_owasp_benchmark_sample` suite=owasp-benchmark-llm-sample status=ok n=12
- `llm_then_securibench_micro_sample` suite=securibench-micro-llm-sample status=ok n=12
- `llm_then_vul4j_sample` suite=vul4j-llm-sample status=ok n=12
- `sast_regex_cvefixes_java_slice` suite=cvefixes-java-slice status=ok n=92
- `sast_regex_find_sec_bugs` suite=find-sec-bugs status=ok n=79
- `sast_regex_juliet` suite=juliet-sast status=ok n=20728
- `sast_regex_owasp_benchmark` suite=owasp-benchmark status=ok n=2740
- `sast_regex_securibench_micro` suite=securibench-micro status=ok n=119
- `sast_regex_vul4j` suite=vul4j status=ok n=62
- `template_cvefixes_java_slice_sample` suite=cvefixes-java-slice-llm-sample status=ok n=12
- `template_find_sec_bugs_sample` suite=find-sec-bugs-llm-sample status=ok n=12
- `template_juliet_sample` suite=juliet-llm-sample status=ok n=72
- `template_owasp_benchmark_sample` suite=owasp-benchmark-llm-sample status=ok n=12
- `template_securibench_micro_sample` suite=securibench-micro-llm-sample status=ok n=12
- `template_vul4j_sample` suite=vul4j-llm-sample status=ok n=12
