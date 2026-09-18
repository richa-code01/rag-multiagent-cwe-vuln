# Empirical Evaluation of LLM Enhancement Techniques

## Background

A software vulnerability is a flaw caused by weaknesses such as buffer overflows, authentication errors, code injection, or design deficiencies in the source code. These weaknesses can be exploited by attackers to bypass security measures and gain unauthorized access to systems.

Vulnerability detection involves identifying security weaknesses in software code that could be exploited by attackers. Conventional detection approaches, such as rule-based and signature-based techniques, rely on predefined patterns to identify known vulnerabilities. However, they often struggle to detect novel, evolving, or sophisticated threats.

This study presents an empirical evaluation of three distinct LLM enhancement techniques against a baseline model, **LLaMA 3.2-3B**, to determine which approach is most effective for detecting software vulnerabilities.

The techniques compared are:

- **Retrieval-Augmented Generation (RAG)**
- **Supervised Fine-Tuning (SFT)**
- **Dual-Agent LLM framework**

## Database Used

A curated dataset was compiled from **Big-Vul** [1] and real-world code repositories from GitHub, focusing on five critical Common Weakness Enumeration (**CWE**) categories: **CWE-119**, **CWE-399**, **CWE-264**, **CWE-20**, and **CWE-200**.


**RAG** approach integrated external domain knowledge from the internet and the **MITRE CWE** database. It achieved the highest overall accuracy (**0.86**) and F1 score (**0.85**), highlighting the value of contextual augmentation.

**SFT** approach, implemented using parameter-efficient **QLoRA** adapters, also demonstrated strong performance.

The **Dual-Agent** system, in which a secondary agent audits and refines the output of the first, showed promise in improving reasoning transparency and error mitigation, while keeping resource overhead lower.

Overall, these results emphasize that incorporating a domain expertise mechanism significantly strengthens the practical applicability of LLMs in real-world vulnerability detection tasks.

