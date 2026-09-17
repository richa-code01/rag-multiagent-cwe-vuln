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
        "Assignments 1–4 and the wired seed pipeline are implemented (PRs #1–#10), "
        "then MiniLM embeddings and a Groq LLM reasoner (embeddings-llm). Research "
        "evaluation is complete on an authored expanded Java corpus (36 units: original "
        "12 plus 24 held-out FP/FN traps) — that table is not a public benchmark. Six "
        "named Java suites were measured: Juliet SAST n=20728 F1=0.316 / Groq sample n=72 "
        "F1=0.733; OWASP n=2740 F1=0.395 / Groq n=12 F1=0.286; Securibench n=119 F1=0.072 "
        "/ Groq n=12 F1=0.500; find-sec-bugs n=79 F1=0.435 / Groq n=12 F1=0.364; Vul4J "
        "n=62 F1=0.244 / Groq n=12 F1=0.000; CVEfixes-Java-slice n=92 F1=0.207 / Groq "
        "n=12 F1=0.000. No HTTP 429. LLM samples are not full suites; regex is not CodeQL. "
        "Six suites do not prove 100% novelty. "
        "The system of record is live Groq openai/gpt-oss-20b. "
        "GROQ_API_KEY is required. No OpenAI account is required.",
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
        "The implemented architecture combines regex SAST evidence, hybrid CWE retrieval "
        "(MiniLM cosine with TF-IDF fallback, SAST ids, CWE relationships, RRF), a cost-aware "
        "orchestrator, a Groq LLMReasoner that emits Assignment-4 schema JSON, an optional "
        "template reasoner for paper ablations, and a validator. GROQ_API_KEY (or "
        "CWE_VULN_LLM_API_KEY override) is required on the default path. No OpenAI account "
        "is required; OPENAI_API_KEY is unused. This is not claimed as SOTA or as the first "
        "RAG-CWE detector; the contribution is this specific composition on an authored trap split.",
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
        "The hybrid retrieval layer ranks curated CWE entries using MiniLM cosine when the local "
        "all-MiniLM-L6-v2 model is available, otherwise TF-IDF, plus SAST-matched CWE ids and "
        "one-hop CWE relationships, fused with Reciprocal Rank Fusion. If MiniLM cannot load, "
        "results record embedder=tfidf_fallback. Retrieval confidence is not a vulnerability decision.",
    )

    set_para(
        doc,
        44,
        "The cost-aware orchestrator always extracts SAST evidence first, then Groq decides. "
        "Pipeline.default() requires GROQ_API_KEY or CWE_VULN_LLM_API_KEY; missing key fails "
        "clearly. Default paths are sast_then_llm / hybrid_retrieve_then_llm. TemplateReasoner "
        "is --offline / --ablation template only (F1=0 on research_test). Default model is Groq "
        "openai/gpt-oss-20b at https://api.groq.com/openai/v1. "
        "No OpenAI account is required; OPENAI_API_KEY is unused.",
    )

    set_para(
        doc,
        45,
        "The validator checks schema validity, that the cited CWE exists in the knowledge store, "
        "that supporting source lines exist in the Java unit, and that the JSON is internally "
        "consistent. It does not require the decision to match SAST: empty SAST evidence with a "
        "vulnerable Groq decision is a sast_disagreement warning, not a failed unit. Framework "
        "metrics compare decisions to labels.",
    )

    set_para(
        doc,
        55,
        "The live pipeline is implemented and runnable: uv sync && uv run pytest && "
        "uv run cwe-vuln-pipeline (requires GROQ_API_KEY). Assignment 1 detection on 12 units "
        "P=R=F1=1.000 (seed-only). Research evaluation on 24 held-out authored traps: "
        "SAST/template P=R=F1=0.000 (12 FP / 12 FN, ablation); live Groq then_llm "
        "P=0.857 R=1.000 F1=0.923, validator 24/24 (was 2/24 under the old SAST-iff-vulnerable "
        "rule). Retrieval on 48 authored queries: hybrid "
        "R@1=0.854 MRR=0.917 vs MiniLM 0.812 / 0.894 vs TF-IDF 0.646 / 0.794. "
        "Juliet Java v1.3 mapped subset (measured): SAST n=20728 P=0.300 R=0.334 F1=0.316; "
        "Groq stratified sample n=72 P=0.917 R=0.611 F1=0.733. Six-suite table: OWASP "
        "n=2740 F1=0.395; Securibench n=119 F1=0.072; find-sec-bugs n=79 F1=0.435; Vul4J "
        "n=62 F1=0.244; CVEfixes-Java-slice n=92 F1=0.207. LLM n=12 on those five "
        "(F1 0.286 / 0.500 / 0.364 / 0.000 / 0.000). No 429. NIST zip 403; GitHub mirror.",
    )

    # Section 12 next steps: remaining honest gaps
    set_para(doc, 57, "Keep the original 12-unit Java seed as the assignment split; research scores use the 24-unit held-out authored traps.")
    set_para(doc, 58, "Optional later: expand the curated CWE store without scraping an unofficial full dump.")
    set_para(doc, 59, "MiniLM embeddings are implemented with TF-IDF fallback if the local model is missing.")
    set_para(doc, 60, "Keep SAST as evidence extraction (CWE hints); knowledge layer owns descriptions.")
    set_para(doc, 61, "Keep SAST as evidence extraction; Groq LLMReasoner is the default decision path (GROQ_API_KEY required).")
    set_para(doc, 62, "Live LLM reasoner is the system of record; research trials used Groq openai/gpt-oss-20b (llama-3.1-8b-instant retired).")
    set_para(doc, 63, "Validator checks schema, CWE id, cited lines, and JSON consistency. SAST disagreement is a warning, not a fail.")
    set_para(doc, 64, "Optional later: richer confidence fusion beyond template confidence fields.")
    set_para(doc, 65, "Six public Java suites measured (Juliet SAST n=20728; others exact n in six-benchmark-results.md). LLM samples are not full suites. Authored 36-unit scores stay a separate table.")

    set_para(
        doc,
        70,
        "The thesis has progressed from study of Explainable AI, RAG and agentic systems to a "
        "runnable live Groq pipeline for explainable CWE-oriented vulnerability detection. The "
        "implemented path combines a curated CWE knowledge store, MiniLM/TF-IDF hybrid retrieval, "
        "regex SAST evidence, Groq LLMReasoner (GROQ_API_KEY required; CWE_VULN_LLM_API_KEY "
        "override), validation that is not tied to SAST agreement, and cost-aware orchestrator routing.",
    )

    set_para(
        doc,
        71,
        "Current work establishes the problem, layered architecture, MiniLM embeddings, "
        "an LLM reasoner, authored-corpus research evaluation, Juliet Java v1.3 mapped "
        "subset, and five additional public Java suites (OWASP Benchmark, Securibench Micro, "
        "find-sec-bugs, Vul4J, CVEfixes-Java-slice). Do not mix the 36-unit authored table "
        "with the six-suite table.",
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
        ("Hybrid retrieval", "Implemented", "MiniLM cosine + SAST + CWE relationships, RRF. TF-IDF fallback if MiniLM missing."),
        ("Cost-aware routing", "Implemented", "Orchestrator SAST-as-evidence then Groq; GROQ_API_KEY required (CWE_VULN_LLM_API_KEY override)."),
        ("Multi-agent workflow", "Implemented", "Groq LLMReasoner default; template ablation; validator (schema/lines/KB)."),
        ("Implementation / evaluation", "Six suites measured", "Authored 36-unit corpus plus six public Java suites (Juliet n=20728 SAST; others in six-benchmark-results.md). Not 100% novelty."),
    ]
    for i, (a, b, c) in enumerate(rows):
        set_cell(t4.rows[i].cells[0], a)
        set_cell(t4.rows[i].cells[1], b)
        set_cell(t4.rows[i].cells[2], c)

    tree = (
        "src/cwe_vuln/\n"
        "  config.py\n"
        "  models/          Evidence, RankedHit, ReasoningResult, ValidationReport, metrics\n"
        "  dataset/         SeedUnit, load_seed 8/4, load_research_corpus 36, six suite adapters\n"
        "  knowledge/       CWEKnowledgeBase\n"
        "  sast/            regex detect + extract_evidence\n"
        "  retrieval/       MiniLM Embedder + TF-IDF fallback + SAST + RRF\n"
        "  schema/          JSON Schema validate helpers\n"
        "  reasoner/        TemplateReasoner + LLMReasoner\n"
        "  validator/       ResultValidator\n"
        "  orchestrator/    Pipeline.default requires Groq; Pipeline.offline ablation\n"
        "  framework/       cwe-vuln-pipeline + cwe-vuln-eval\n"
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
        ("Hybrid retrieval", "Implemented", "MiniLM with TF-IDF fallback; seed-only metrics in results/."),
        ("Cost-aware orchestrator", "Implemented", "SAST evidence then Groq; missing GROQ_API_KEY fails clearly."),
        ("Reasoning agent", "Implemented", "LLMReasoner default (openai/gpt-oss-20b); TemplateReasoner is ablation."),
        ("Validator agent", "Implemented", "Schema, CWE id, cited lines, JSON consistency. SAST disagreement is a warning."),
        ("Layered packages", "Implemented", "models, dataset, knowledge, sast, retrieval, schema, reasoner, validator, orchestrator, framework, cli."),
        ("Reporting", "Implemented", "Assignment 4 JSON Schema + framework results JSON/MD."),
        ("Evaluation", "Six suites measured", "Juliet SAST n=20728 F1=0.316 Groq n=72 F1=0.733; five more suites with exact n. Authored 36-unit table is separate."),
    ]
    for i, (a, b, c) in enumerate(rows8):
        set_cell(t8.rows[i].cells[0], a)
        set_cell(t8.rows[i].cells[1], b)
        set_cell(t8.rows[i].cells[2], c)

    set_cell(
        doc.tables[9].rows[0].cells[0],
        "Progress summary: XAI → RAG → CWE knowledge → agentic AI → Java seed + SAST baseline "
        "→ hybrid retrieval → schema → evidence → template reasoner → validator → "
        "orchestrator → framework CLI → layered packages → MiniLM embeddings + LLM "
        "reasoner → research evaluation on an authored expanded corpus → live Groq default "
        "with validator uncoupled from SAST → Juliet Java v1.3 mapped-subset eval "
        "(SAST n=20728, Groq sample n=72) → six public Java suites (OWASP, Securibench, "
        "find-sec-bugs, Vul4J, CVEfixes-Java-slice).",
    )

    set_cell(
        doc.tables[0].rows[0].cells[0],
        "Research focus: RAG-augmented multi-agent CWE vulnerability detection. The live path is "
        "regex SAST evidence, MiniLM/TF-IDF hybrid retrieval, Groq LLMReasoner, and a validator "
        "that checks schema/lines/KB rather than SAST agreement. Template/SAST are paper ablations.",
    )

    doc.save(str(SRC))
    doc.save(str(OFFICIAL))
    print(f"wrote {SRC}")
    print(f"wrote {OFFICIAL}")


if __name__ == "__main__":
    main()
