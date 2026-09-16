"""Update the thesis progress report DOCX in place (template headings kept)."""

from __future__ import annotations

from pathlib import Path

from docx import Document

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "RAG_MultiAgent_Vulnerability_Thesis_Progress_Report.docx"
OFFICIAL = ROOT / "Thesis Progress Report_RichaVerma_25MCSS02.docx"


def set_para(doc: Document, index: int, text: str) -> None:
    para = doc.paragraphs[index]
    if para.runs:
        para.runs[0].text = text
        for run in para.runs[1:]:
            run.text = ""
    else:
        para.add_run(text)


def set_cell(cell, text: str) -> None:
    if cell.paragraphs and cell.paragraphs[0].runs:
        cell.paragraphs[0].runs[0].text = text
        for run in cell.paragraphs[0].runs[1:]:
            run.text = ""
        for extra in cell.paragraphs[1:]:
            extra.clear()
    elif cell.paragraphs:
        cell.paragraphs[0].text = text
    else:
        cell.text = text


def main() -> None:
    doc = Document(str(SRC))

    set_para(
        doc,
        1,
        "RICHA VERMA – 25MCSS02  ·  Advisor: Dr. Akshay Pandey",
    )

    set_para(
        doc,
        28,
        "Assignments 1–4 and the wired seed pipeline are implemented in the GitHub repository "
        "(PRs #1–#9), then reorganized into layered Python packages (modular-layout). "
        "Evaluation is seed-only on 12 authored Java units and 18 retrieval queries — not a "
        "public benchmark (not Juliet, OWASP Benchmark, or Big-Vul). Neural embeddings and a "
        "live LLM reasoner are not implemented. The default path is offline: regex SAST, "
        "lexical TF-IDF hybrid retrieval, and a template reasoner.",
    )

    set_para(
        doc,
        30,
        "The repository now uses layered subpackages under src/cwe_vuln/ (models, dataset, "
        "knowledge, sast, retrieval, schema, reasoner, validator, orchestrator, framework, cli). "
        "Shared DTOs live in models/. Tests mirror those packages. data/ remains the corpus; "
        "Java seeds are not inside the Python package.",
    )

    set_para(
        doc,
        39,
        "The implemented architecture combines regex SAST evidence, lexical hybrid CWE retrieval, "
        "a cost-aware orchestrator, a template reasoning composer, and a validator. LLM reasoning "
        "is specified as an optional later path; the running system skips it when no API key is "
        "set or when SAST evidence is already present.",
    )

    set_para(
        doc,
        42,
        "The SAST layer runs seed-oriented regex rules and emits Evidence objects (file, lines, "
        "snippet, CWE id hint). It does not embed CWE encyclopedia text; names and mitigations "
        "come from the knowledge store. A “safe” regex result is not treated as a hard proof of "
        "absence — the pipeline still retrieves CWE context for explanation.",
    )

    set_para(
        doc,
        43,
        "The hybrid retrieval layer ranks curated CWE entries using lexical TF-IDF cosine, "
        "SAST-matched CWE ids, and one-hop CWE relationships, fused with Reciprocal Rank Fusion. "
        "This is a lexical vector space, not neural MiniLM embeddings. Retrieval confidence is "
        "not used as a vulnerability decision.",
    )

    set_para(
        doc,
        44,
        "The cost-aware orchestrator runs SAST first. If evidence exists, or if no API key is "
        "configured (CWE_VULN_LLM_API_KEY / OPENAI_API_KEY), the LLM is skipped. The running "
        "reasoner is a deterministic template composer that emits Assignment 4 JSON Schema output.",
    )

    set_para(
        doc,
        45,
        "The validator checks schema validity, that the cited CWE exists in the knowledge store, "
        "that supporting source lines exist in the Java unit, and that the decision is consistent "
        "with SAST evidence. Framework metrics compare decisions to seed labels.",
    )

    set_para(
        doc,
        55,
        "The seed pipeline is implemented and runnable: uv sync && uv run pytest && "
        "uv run cwe-vuln-pipeline. Recorded seed-only scores: Assignment 1 detection on 12 units "
        "P=R=F1=1.000 (tp=6 fp=0 tn=6 fn=0); Assignment 3 hybrid_rrf on 18 queries R@1=0.778 "
        "R@3=0.944 R@5=1.000 MRR=0.872; framework test split (4 units) P=R=F1=1.000, validator "
        "4/4, paths sast_first_skip_llm=2 and hybrid_retrieve_skip_llm=2. Remaining work is neural "
        "embeddings, a live LLM reasoner, and any later public-benchmark evaluation — none of "
        "those are claimed here.",
    )

    # Section 12 next steps: remaining honest gaps
    set_para(doc, 57, "Keep the 12-unit Java seed as a pedagogical corpus; do not treat it as Juliet/OWASP Benchmark.")
    set_para(doc, 58, "Optional later: expand the curated CWE store without scraping an unofficial full dump.")
    set_para(doc, 59, "Optional later: swap TF-IDF for a local MiniLM encoder if embeddings can be installed offline.")
    set_para(doc, 60, "Keep SAST as evidence extraction (CWE hints); knowledge layer owns descriptions.")
    set_para(doc, 61, "Keep SAST-first skip-LLM routing in the orchestrator unless a real API key path is added.")
    set_para(doc, 62, "Optional later: implement a live LLM reasoner behind CWE_VULN_LLM_API_KEY / OPENAI_API_KEY; do not fake outputs.")
    set_para(doc, 63, "Validator already checks schema, CWE id, cited lines, and decision vs evidence.")
    set_para(doc, 64, "Optional later: richer confidence fusion beyond template confidence fields.")
    set_para(doc, 65, "Public-benchmark experiments remain out of scope until a labeled external dataset is adopted.")

    set_para(
        doc,
        70,
        "The thesis has progressed from study of Explainable AI, RAG and agentic systems to a "
        "runnable seed-only pipeline for explainable CWE-oriented vulnerability detection. The "
        "implemented path combines a curated CWE knowledge store, lexical hybrid retrieval, "
        "regex SAST evidence, a template reasoner, validation, and cost-aware skip-LLM routing.",
    )

    set_para(
        doc,
        71,
        "Current work establishes the problem, layered architecture, and a complete offline seed "
        "pipeline with recorded seed-only metrics. Neural embeddings, a live LLM reasoner, and "
        "public-benchmark evaluation remain future work and are not reported as done.",
    )

    # Table 4 — area / status / progress
    t4 = doc.tables[4]
    rows = [
        ("Area", "Status", "Current progress"),
        ("XAI and explainability", "Studied", "Covered explainability, SHAP, counterfactuals and faithfulness-related concepts."),
        ("RAG", "Studied", "Understood retrieval, grounding and the role of external knowledge."),
        ("Agentic AI", "Studied", "Defined specialized agents and orchestration."),
        ("CWE security knowledge", "Implemented", "Curated store + query API (PR #2). Teaching subset, not a MITRE dump."),
        ("Vulnerability detection problem", "Defined", "Focused on precision, false positives, false negatives and explainability."),
        ("Static analysis role", "Implemented", "Regex SAST + Evidence spans (PRs #1, #5). Seed-only baseline P=R=F1=1.000."),
        ("Hybrid retrieval", "Implemented", "Lexical TF-IDF + SAST + CWE relationships, RRF (PR #3). Not neural embeddings."),
        ("Cost-aware routing", "Implemented", "Orchestrator SAST-first skip-LLM (PR #8)."),
        ("Multi-agent workflow", "Implemented", "Reasoner, validator, framework CLI (PRs #6, #7, #9)."),
        ("Implementation / evaluation", "Seed pipeline done", "Layered packages; seed-only metrics recorded. No public benchmark."),
    ]
    for i, (a, b, c) in enumerate(rows):
        set_cell(t4.rows[i].cells[0], a)
        set_cell(t4.rows[i].cells[1], b)
        set_cell(t4.rows[i].cells[2], c)

    tree = (
        "src/cwe_vuln/\n"
        "  config.py\n"
        "  models/          Evidence, RankedHit, ReasoningResult, ValidationReport, metrics\n"
        "  dataset/         SeedUnit, load_seed, 8/4 split\n"
        "  knowledge/       CWEKnowledgeBase\n"
        "  sast/            regex detect + extract_evidence\n"
        "  retrieval/       TF-IDF + SAST + relationships + RRF\n"
        "  schema/          JSON Schema validate helpers\n"
        "  reasoner/        TemplateReasoner\n"
        "  validator/       ResultValidator\n"
        "  orchestrator/    Pipeline, skip-LLM policy\n"
        "  framework/       cwe-vuln-pipeline CLI\n"
        "  cli/             baseline, kb, retrieve, schema, evidence\n"
        "data/  docs/  results/  schemas/  tests/ (mirrors packages)"
    )
    set_cell(doc.tables[5].rows[0].cells[0], tree)

    t8 = doc.tables[8]
    rows8 = [
        ("Component", "Status", "Next step"),
        ("Research direction", "Defined", "Continue literature study around vulnerability detection, RAG and multi-agent systems."),
        ("Problem formulation", "Completed", "Keep evaluation criteria seed-only until an external dataset is adopted."),
        ("CWE knowledge layer", "Implemented", "Optional: enlarge the curated subset; do not scrape a messy dump."),
        ("Static analysis", "Implemented", "Regex evidence extraction on the 12-unit Java seed."),
        ("Hybrid retrieval", "Implemented", "Optional later: MiniLM embeddings if they install cleanly."),
        ("Cost-aware orchestrator", "Implemented", "SAST-first skip-LLM; live LLM still unimplemented."),
        ("Reasoning agent", "Implemented (template)", "Optional later: real LLM client if an API key is available."),
        ("Validator agent", "Implemented", "Schema, CWE id, cited lines, decision vs evidence."),
        ("Layered packages", "Implemented", "models, dataset, knowledge, sast, retrieval, schema, reasoner, validator, orchestrator, framework, cli."),
        ("Reporting", "Implemented", "Assignment 4 JSON Schema + framework results JSON/MD."),
        ("Evaluation", "Seed-only", "No Juliet / OWASP Benchmark / Big-Vul numbers. Do not invent them."),
    ]
    for i, (a, b, c) in enumerate(rows8):
        set_cell(t8.rows[i].cells[0], a)
        set_cell(t8.rows[i].cells[1], b)
        set_cell(t8.rows[i].cells[2], c)

    set_cell(
        doc.tables[9].rows[0].cells[0],
        "Progress summary: XAI → RAG → CWE knowledge → agentic AI → Java seed + SAST baseline "
        "→ hybrid lexical retrieval → schema → evidence → template reasoner → validator → "
        "orchestrator → framework CLI → layered packages. Remaining: neural embeddings, live LLM, "
        "public-benchmark evaluation.",
    )

    set_cell(
        doc.tables[0].rows[0].cells[0],
        "Research focus: RAG-augmented multi-agent CWE vulnerability detection. Runnable path is "
        "seed-only (regex SAST, lexical hybrid retrieval, template reasoner, validator). Cost-aware "
        "skip-LLM routing lives in the orchestrator.",
    )

    doc.save(str(SRC))
    doc.save(str(OFFICIAL))
    print(f"wrote {SRC}")
    print(f"wrote {OFFICIAL}")


if __name__ == "__main__":
    main()
