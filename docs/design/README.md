# Design documentation

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

These documents are the system design of record for `cwe-vuln`. They describe the **as-built** Python package and the **production-grade** contracts (security, reliability, observability, operations) that a shippable system of this type must hold.

| Document | Audience | Contents |
| --- | --- | --- |
| [HLD](hld.md) | Advisor, reviewers, operators | Context, C4, NFRs, security, data, integrations, failure modes, ops |
| [LLD](lld.md) | Maintainers, contributors | Modules, APIs, sequences, algorithms, schemas, errors, config, tests |
| [Architecture snapshot](../architecture.md) | Fast orientation | Package tree and layer rules (kept short) |

**Honesty rule:** the running system is a research CLI (single-process, no HTTP API, no multi-tenant auth). The HLD still specifies production NFRs and the gaps against them so we do not pretend a SaaS exists. Code paths, env names, schemas, and CLIs are taken from `src/cwe_vuln/` and `pyproject.toml`, not invented.

Related operational docs:

- Advisor sequence: [`../advisor-phase-plan.md`](../advisor-phase-plan.md)
- Orchestrator cost policy: [`../orchestrator.md`](../orchestrator.md)
- Schema contract: [`../../schemas/reasoning_output.schema.json`](../../schemas/reasoning_output.schema.json)
- Public-suite SAST (kept) vs retracted LLM rows: [`../six-benchmark-results.md`](../six-benchmark-results.md)
