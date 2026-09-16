# Assignment 2: CWE knowledge layer

Thesis: **RAG-Augmented Multi-Agent LLM Framework for Explainable Software Vulnerability Detection Using CWE Knowledge Bases**
Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey

This assignment adds a **curated structured CWE store** and a **Python query interface**. It does **not** add hybrid retrieval, RAG embeddings, or a reasoning agent.

## Store

- Path: `data/cwe/knowledge.json`
- Format: JSON object with `meta` + `entries[]`
- Coverage: the six seed CWEs (89, 79, 22, 502, 798, 327) plus related parents/children/peers used for relationship walks (for example CWE-943, CWE-74, CWE-259, CWE-328)
- Provenance: a teaching subset **derived from public CWE/MITRE catalog facts** (names, high-level descriptions, common mitigations, published relationships). **Not an official MITRE dump** and not a complete CWE database. No invented CWE identifiers.

Each entry has: `id`, `name`, `description`, `relationships` (`parents` / `children` / `peers`), `mitigations[]`, `detection_notes`.

## Query interface

`CWEKnowledgeBase` in `src/cwe_vuln/knowledge/` (`from cwe_vuln.knowledge import CWEKnowledgeBase`):

| Method | Role |
| --- | --- |
| `CWEKnowledgeBase.load()` | Load the JSON store |
| `get(cwe_id)` | Lookup by `CWE-89` or `89` |
| `search(text)` | Token overlap over name, description, mitigations |
| `relationships(cwe_id)` | Parent / child / peer ids |
| `mitigations(cwe_id)` | Mitigation records |
| `neighbors(cwe_id)` | Resolved one-hop entries that exist in this subset |

`search` is lexical (token overlap). Semantic / hybrid retrieval is Assignment 3.

## Sample queries

```bash
uv run cwe-vuln-kb get CWE-89
uv run cwe-vuln-kb search "sql injection"
uv run cwe-vuln-kb relationships CWE-798
uv run cwe-vuln-kb mitigations CWE-22
uv run cwe-vuln-kb demo
```

Expected demo shape (ids, not a benchmark):

- `get CWE-89` returns SQL Injection and parameterized-query mitigations
- `search "cross site scripting"` ranks CWE-79 near the top
- `relationships CWE-798` includes children CWE-259 and CWE-321
- `mitigations CWE-22` includes resolve-and-constrain-the-path

## What this is not

- Not hybrid retrieval (Assignment 3)
- Not a structured reasoning schema (Assignment 4)
- Not a multi-agent system
- Not a full official CWE download
