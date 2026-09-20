# Chapter 2 — Related work

Citations below are the six PDFs in `research-papers/` plus MITRE CWE and the public suite repositories already used in this tree. Venues printed as running headers in PDFs are **not** treated as confirmed acceptances.

| Paper (local file) | Language / corpus | Retrieval | Agents | Validator | Gap vs this thesis |
| --- | --- | --- | --- | --- | --- |
| RP1 (`RP1.pdf`) | C/C++ (Big-Vul) + partner **GlassHouse** traces (not generic GitHub dumps) | RAG over web + MITRE CWE | Dual-agent audit | LLM-side | Not Java; not six web CWEs; not A4 schema + deterministic validator |
| MultiVer (`MultiVer_RP.pdf`) | Python | Multi-view | Multi-agent | — | Different language |
| MulVul (`MulVul_Retrieval-augmented_Multi-Agent_Code_Vulner.pdf`) | C/C++ | RAG over code examples | Multi-agent | — | Unstructured/example retrieval, not structured CWE entries |
| MAVUL (`MaVulpdf`) | C/C++ | — | Multi-agent; pairwise scoring | — | Pair metric inspired C2; not Java CWE KB |
| HeterogenousMAS (`HeterogenousMAS.pdf`) | C/C++ | — | Heterogeneous agents; LLM verifier | LLM verifier | We keep a **rule-based** validator by design |
| MARVEL (`MARVEL_RP.pdf`) | RTL hardware | — | Multi-agent | Human-light adjudication | Different domain; C8 copies the lightweight spot-check idea only |

**Honest gap we fill:** Java + CWE-89/79/22/502/798/327 (+ nearby public-suite ids, not relabeled) + structured CWE fields (description, mitigations, relationships) in the LLM prompt + schema `{decision, CWE, cited lines, root cause, explanation, remediation}` + deterministic validator.

MITRE CWE: official XML catalog, subset committed with `catalog_version` / `catalog_date` in `data/cwe/knowledge.json`. Suites: NIST Juliet Java 1.3, OWASP Benchmark, Securibench Micro, Find Security Bugs test-code, Vul4J, CVEfixes-Java-slice (GitHub Advisory maven slice, not the full Zenodo dump).
