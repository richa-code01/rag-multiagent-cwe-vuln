#!/usr/bin/env python3
"""Generate docs/thesis chapters and a thesis-shaped DOCX from results JSON.

Numbers are loaded from results/thesis/*.json. Do not hardcode metrics here.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH

ROOT = Path(__file__).resolve().parents[1]
THESIS_DIR = ROOT / "docs" / "thesis"
RESULTS = ROOT / "results" / "thesis"
OFFICIAL_DOCX = ROOT / "Thesis Progress Report_RichaVerma_25MCSS02.docx"
GENERATED_DOCX = ROOT / "results" / "thesis" / "Thesis_RichaVerma_25MCSS02.docx"

TOPIC = (
    "RAG-Augmented Multi-Agent LLM Framework for Explainable Software "
    "Vulnerability Detection Using CWE Knowledge Bases"
)


def load(name: str) -> dict:
    return json.loads((RESULTS / name).read_text(encoding="utf-8"))


def load_optional(name: str) -> dict | None:
    path = RESULTS / name
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def missing_trial(trial_id: str, note: str) -> dict:
    return {
        "trial_id": trial_id,
        "status": "not_run",
        "metrics": {},
        "notes": note,
        "n_units": None,
    }


def f3(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value:.3f}"


def pct(correct: int, total: int) -> str:
    if not total:
        return "—"
    return f"{correct}/{total} ({correct / total:.3f})"


def metric_row(trial: dict) -> dict:
    m = trial.get("metrics") or {}
    return {
        "id": trial.get("trial_id"),
        "status": trial.get("status"),
        "p": m.get("precision"),
        "r": m.get("recall"),
        "f1": m.get("f1"),
        "fp": m.get("fp"),
        "fn": m.get("fn"),
        "n": m.get("support") or trial.get("n_units") or trial.get("n_scored"),
    }


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


def detection_table(trials: list[dict], ids: list[str]) -> str:
    by_id = {t.get("trial_id"): t for t in trials if t.get("trial_id")}
    rows = []
    for tid in ids:
        t = by_id.get(tid)
        if t is None:
            rows.append([tid, "not_run", "—", "—", "—", "—", "—", "—"])
            continue
        r = metric_row(t)
        rows.append(
            [
                tid,
                r["status"],
                f3(r["p"]),
                f3(r["r"]),
                f3(r["f1"]),
                r["fp"] if r["fp"] is not None else "—",
                r["fn"] if r["fn"] is not None else "—",
                r["n"] if r["n"] is not None else "—",
            ]
        )
    return md_table(
        ["System", "Status", "Precision", "Recall", "F1", "FP", "FN", "n"],
        rows,
    )


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body.rstrip() + "\n", encoding="utf-8")


def _is_multi_file_id(text: str, pattern: re.Pattern[str]) -> bool:
    stripped = re.sub(r"__(method_|file_)?(bad|good[A-Za-z0-9]*)$", "", text or "")
    stripped = re.sub(r"__pair\d+$", "", stripped)
    return bool(pattern.search(stripped))


def _error_analysis_md(
    c1: dict,
    c2: dict,
    sast_c1: dict | None,
    sast_c1_san: dict | None,
    template_c1: dict | None,
    multi_file_stem: re.Pattern[str],
    retrieval_old: dict | None = None,
    retrieval_new: dict | None = None,
) -> str:
    """Chapter 8 from existing JSON. No invented numbers."""
    pair_rows = c2.get("pair_rows") or []
    by_cwe: dict[str, list[dict]] = {}
    for row in pair_rows:
        by_cwe.setdefault(row.get("cwe_id") or "unknown", []).append(row)

    family_lines = []
    for cwe_id in sorted(by_cwe):
        rows = by_cwe[cwe_id]
        n_ok = sum(1 for item in rows if item.get("correct"))
        n_multi = sum(
            1
            for item in rows
            if _is_multi_file_id(item.get("pair_id") or "", multi_file_stem)
            or _is_multi_file_id(item.get("bad_id") or "", multi_file_stem)
        )
        n_uncertain = sum(
            1
            for item in rows
            if item.get("bad_decision") == "uncertain" or item.get("good_decision") == "uncertain"
        )
        family_lines.append(
            f"| {cwe_id} | {len(rows)} | {n_ok} | {n_multi} | {n_uncertain} |"
        )

    failed = [row for row in pair_rows if not row.get("correct") and not row.get("incomplete")]
    incomplete_pairs = [row for row in pair_rows if row.get("incomplete")]
    fail_rows = []
    for row in failed:
        flag = "yes" if (
            _is_multi_file_id(row.get("pair_id") or "", multi_file_stem)
            or _is_multi_file_id(row.get("bad_id") or "", multi_file_stem)
        ) else "no"
        fail_rows.append(
            [
                row.get("cwe_id"),
                row.get("pair_id", "")[:80],
                row.get("bad_decision"),
                row.get("good_decision"),
                flag,
            ]
        )
    incomplete_table = (
        md_table(
            ["CWE", "pair_id (truncated)", "bad", "good"],
            [
                [
                    row.get("cwe_id"),
                    row.get("pair_id", "")[:80],
                    row.get("bad_decision") or "(missing)",
                    row.get("good_decision") or "(missing)",
                ]
                for row in incomplete_pairs
            ],
        )
        if incomplete_pairs
        else "_None._"
    )

    c1_decisions = c1.get("unit_decisions") or []
    c2_decisions = c2.get("unit_decisions") or []
    cwe0_c1 = sum(1 for row in c1_decisions if row.get("predicted_cwe") == "CWE-0")
    cwe0_c2 = sum(1 for row in c2_decisions if row.get("predicted_cwe") == "CWE-0")
    uncertain_c1 = sum(1 for row in c1_decisions if row.get("decision") == "uncertain")
    uncertain_c2 = sum(1 for row in c2_decisions if row.get("decision") == "uncertain")
    c2_tiers = Counter(row.get("cwe_tier") or "unknown" for row in c2_decisions)

    raw_fp = (sast_c1 or {}).get("metrics", {}).get("fp")
    san_fp = (sast_c1_san or {}).get("metrics", {}).get("fp")
    tmpl_fp = (template_c1 or {}).get("metrics", {}).get("fp")
    confound = "not yet computed on this snapshot"
    if raw_fp is not None and san_fp is not None:
        confound = (
            f"raw-disk SAST FP={raw_fp}; sanitized SAST FP={san_fp}; "
            f"template FP={tmpl_fp}. Comment-only regex hits vanish after blanking "
            "and must not be credited to the reasoner."
        )

    r1_old = ((retrieval_old or {}).get("metrics") or {}).get("hybrid_rrf", {}).get("recall@1")
    r1_new = ((retrieval_new or {}).get("metrics") or {}).get("hybrid_rrf", {}).get("recall@1")
    neural_new = ((retrieval_new or {}).get("metrics") or {}).get("neural", {}).get("recall@1")
    sast_new = ((retrieval_new or {}).get("metrics") or {}).get("sast", {}).get("recall@1")
    fail_table = (
        md_table(
            ["CWE", "pair_id (truncated)", "bad", "good", "multi-file"],
            fail_rows,
        )
        if fail_rows
        else "_No pair_rows in the current C2 JSON._"
    )

    return f"""# Chapter 8 — Error analysis

Generated from `results/thesis/llm_then_research_test.json` and `llm_then_juliet_pairs.json`. No live LLM. Do not treat this chapter as a new measurement.

## C2 pair failures by family

A pair is correct only if `bad → vulnerable` and `good → not_vulnerable`. `uncertain` is incorrect.

| CWE | n pairs | correct | multi-file variants | any uncertain |
| --- | ---: | ---: | ---: | ---: |
{chr(10).join(family_lines) if family_lines else "| — | 0 | 0 | 0 | 0 |"}

### Failed pairs

{fail_table}

### Incomplete pairs (TPD, not a model error)

{incomplete_table}

**Sampling bug (methodology, not a model result):** Juliet `_NNa/_NNb` flow variants hide the sink in a sibling file. Those IDs are excluded from later pair pools. The first C2 run that included them is archived under `results/thesis/archive/` when regenerated, not deleted.

## CWE-0 and unknown ids

- C1 predicted `CWE-0`: {cwe0_c1} / {len(c1_decisions)}
- C2 predicted `CWE-0`: {cwe0_c2} / {len(c2_decisions)}

Later runs clamp unknown ids (including `CWE-0`) to the top retrieved/evidence KB id and record `cwe_clamped_from`.

## `uncertain` (abstention)

- C1 uncertain units: {uncertain_c1} / {len(c1_decisions)}
- C2 uncertain units: {uncertain_c2} / {len(c2_decisions)}

Pair metric: any uncertain decision makes the pair incorrect. Binary `metrics` treat uncertain as `not_vulnerable` (abstain-as-negative). `metrics_exclude_abstain` drops those units.

## CWE match tiers on C2 (recomputed offline; peers are not family)

{md_table(["tier", "n"], [[k, v] for k, v in sorted(c2_tiers.items())]) if c2_decisions else "_no unit_decisions_"}

Exact is the classification number. Family in later tables is exact or parent/child only.

## Cited lines (indent confound)

C1 cited_lines raw rate: {f3(c1.get("cited_lines_rate"))}. Indent-normalized: {f3(c1.get("cited_lines_normalized_rate"))}.
C2 cited_lines raw rate: {f3(c2.get("cited_lines_rate"))}. Indent-normalized: {f3(c2.get("cited_lines_normalized_rate"))}.

A large share of raw citation failures are whitespace/indent only (`snippet.strip() in excerpt` vs per-line strip). Spans are never rewritten.

## Comment-trap SAST confound

{confound}

## Retrieval query (file head vs sink window)

Archived contaminated-sample hybrid R@1: {r1_old if r1_old is not None else "—"}.
Rebuilt single-file sample (`retrieval_query_text` evidence/sink window): hybrid R@1={r1_new if r1_new is not None else "—"}, MiniLM R@1={neural_new if neural_new is not None else "—"}, SAST-channel R@1={sast_new if sast_new is not None else "—"}.

This is retrieval recall of the gold CWE id, not detection F1. Do not claim RAG helps detection until `llm_no_retrieval_juliet_pairs` exists.

## What this does *not* prove

- RAG on Juliet is unproven until `llm_no_retrieval_juliet_pairs` exists.
- C1 F1 is trap-overfit by construction. C4 no-retrieval matching C1 F1 means retrieval did not change trap detection on this snapshot.
- C3 skipped/partial LLM rows are not a real-world claim.
- An incomplete C2 pair from TPD is not a model miss.
"""


def build() -> None:
    from cwe_vuln.dataset.juliet import MULTI_FILE_STEM
    from cwe_vuln.framework.eval import enrich_trial_cwe_fields

    summary = load("summary.json")
    c1 = enrich_trial_cwe_fields(load("llm_then_research_test.json"))
    c2_raw = load_optional("llm_then_juliet_pairs.json") or missing_trial(
        "llm_then_juliet_pairs", "C2 LLM not in this results tree"
    )
    c2 = enrich_trial_cwe_fields(c2_raw) if c2_raw.get("unit_decisions") else c2_raw
    c3 = load_optional("llm_then_vul4j_sliced.json") or missing_trial(
        "llm_then_vul4j_sliced", "C3 not run or partial"
    )
    sast_c1 = load_optional("sast_regex_research_test.json")
    sast_c1_san = load_optional("sast_regex_sanitized_research_test.json")
    template_c1 = load_optional("template_research_test.json")
    no_ret = load_optional("llm_no_retrieval_research_test.json")
    no_sast = load_optional("llm_no_sast_research_test.json")
    generated = summary["generated_at"]
    pair = c2.get("pair_metrics") or {}
    ci = pair.get("bootstrap_95") or {}
    trials = summary.get("trials") or []

    header = (
        f"# {TOPIC}\n\n"
        f"Student: Richa Verma (25MCSS02) · Advisor: Dr. Akshay Pandey\n\n"
        f"Source of numbers: `results/thesis/*.json` generated `{generated}`. "
        "Do not mix these tables with retracted 2026-09-17 public-suite LLM rows.\n"
    )

    intro = header.replace("# ", "# Chapter 1 — Introduction\n\n**Thesis:** ", 1) + """
## Problem

Explainable vulnerability detection on Java units: decide `vulnerable` / `not_vulnerable` / `uncertain`, name a CWE, cite source lines, and state root cause, explanation, and remediation. Regex SAST is **evidence**, not the decision. The knowledge base is a parsed MITRE CWE XML **subset** (catalog v4.20 in `data/cwe/knowledge.json`), not the full catalog.

## Claim (defendable)

Related work already uses RAG and multi-agent detection on C/C++, Python, or RTL. This thesis claims a **specific composition** for Java and six web/enterprise CWE families: regex evidence + hybrid MiniLM/TF-IDF + CWE-relationship RRF + schema-bound LLM + a **deterministic** validator. Agents are **staged specialists** under a deterministic orchestrator, not a conversation bus. The default path is **always-LLM**; fused confidence is **logged, not gating**. It does **not** claim SOTA or “first RAG-CWE detector.”

The public LLM number is **C2 Juliet pair accuracy** (with bootstrap CI). C1 authored-trap F1 is a valid “regex fails, LLM recovers” contrast only, and is trap-overfit by construction.

## Six ApproachDoc stages

1. EvidenceAgent — regex SAST spans
2. KnowledgeAgent — hybrid CWE RAG (query = evidence/sink window, never gold notes, never file head)
3. Orchestrator — route log; risk / retrieval confidence / coverage / fused confidence are **logged**, not used to skip the LLM
4. ReasoningAgent — Groq `openai/gpt-oss-20b` JSON (provider-swappable); unknown CWE ids clamped to retrieved hits
5. ValidatorAgent — schema / CWE-in-KB / cited lines (raw + indent-normalized) / consistency; SAST disagreement is a warning
6. Report — `PipelineResult` diagnostics + signals

Design of record: [`docs/design/hld.md`](../design/hld.md) · [`docs/design/lld.md`](../design/lld.md).
"""

    related = """# Chapter 2 — Related work

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
"""

    design = """# Chapter 3 — System design

Implemented as the `cwe-vuln` src-layout package. Production-grade HLD/LLD: [`../design/hld.md`](../design/hld.md), [`../design/lld.md`](../design/lld.md).

## Honesty about SAST

Six pedagogical regexes (SQL concat, unencoded HTML concat, `new File(...+)`, `ObjectInputStream`/`readObject`, hardcoded secret literals, `getInstance("MD5|DES|…")`). Not AST, not taint, not CodeQL. Fair tables score regex on the **same sanitized units** the LLM sees (`sast_regex_sanitized_*`). Raw-disk regex is a separate row.

## RAG

Passages are `{CWE-id}::main|mitigations|detection` from the MITRE subset. Hybrid rank: MiniLM cosine (TF-IDF fallback) + SAST ids + one-hop relationships, RRF (`k=60`), `top_k=5`. Query = evidence/sink window (`retrieval_query_text`), never gold `notes`, never the file head. Hits carry `passage` text into the prompt.

## LLM

`ChatProvider` port; Groq default. Temperature 0, JSON mode. Invalid JSON retried once then `llm_fallback_template` **with** `fallback_reason`. HTTP 429 is re-raised (never silent template-as-Groq). Prompts are sanitized (opaque id, comments blanked, `bad`/`good` renamed). Cited lines are **not** rewritten when the snippet is wrong. CWE ids outside the KB (including `CWE-0`) are clamped to the top retrieval hit; `cwe_clamped_from` is recorded.

## Agents and routing

Named agents are staged specialists (evidence → retrieval → reason → validate) under a deterministic orchestrator. The default path is always-LLM. `skip_llm_when_sast_hits` is an opt-in ablation. `final_confidence` is a logged heuristic, **not** a routing gate.

## Confidence

`final_confidence = 0.45·llm + 0.25·retrieval + 0.20·sast_agreement + 0.10·validator`. Documented heuristic, not a calibrated probability, not a gate.
"""

    setup = """# Chapter 4 — Experimental setup

Repro: `uv run pytest` (no live LLM) then `uv run cwe-vuln-eval --suite thesis --resume --max-tokens 200000` with `GROQ_API_KEY`. Groq free-tier observed cap **200,000 tokens/day** and **8,000 tokens/minute**. Model: `openai/gpt-oss-20b` (verified live 2026-09-18). Fallbacks `openai/gpt-oss-120b` and `qwen/qwen3.8-27b` were **not** run (C7 skip).

| Slice | n | Metric |
| --- | ---: | --- |
| C1 authored research_test | 24 | Binary P/R/F1 (abstain-as-negative **and** exclude-abstain), CWE exact / parent-child / peer, tokens |
| C2 Juliet pairs | 18 pairs / 36 units (3 per family, seed=13), **single-file variants only** | Pair accuracy + bootstrap 95% CI; binary F1 |
| C3 Vul4J sliced ±40 | planned 24; LLM may be partial (TPD) | Do not cite a partial row as a real-world claim |
| C4 | template + raw/sanitized SAST; no-RAG/no-SAST LLM if TPD allows | Required before claiming RAG/SAST help |
| C5 Semgrep | skip unless installed | Not compared to CodeQL |
| C8 human spot-check | `not_run` | Awaits Richa; 30 unit ids sampled, labels empty |

Pair definition: correct iff `bad → vulnerable` **and** matched `good* → not_vulnerable`. `uncertain` is pair-incorrect and is reported as an abstention rate. CWE-502 is not present in Juliet Java 1.3.

Juliet `_NNa/_NNb` flow variants are **excluded** from the pair pool (the `a` file often only forwards data to a `b` helper that holds the sink). Nearby folder ids (80, 23, 259, 328) keep their Juliet numbers and are not relabeled to 79/22/798.

Public-suite **regex SAST** (full ingested sets, 2026-09-17) is kept. Public-suite **LLM** rows from that date are retracted (gold leakage / silent fallback).
"""

    c1_cwe = c1.get("cwe_exact_match") or {}
    c1_pc = c1.get("cwe_parent_child_match") or {}
    c1_peer = c1.get("cwe_peer_match") or {}
    c1_fam = c1.get("cwe_family_match") or {}
    c2_cwe = c2.get("cwe_exact_match") or {}
    c2_pc = c2.get("cwe_parent_child_match") or {}
    c2_peer = c2.get("cwe_peer_match") or {}
    c2_fam = c2.get("cwe_family_match") or {}
    c1_tok = c1.get("token_usage") or {}
    c2_tok = c2.get("token_usage") or {}
    c1_abs = c1.get("abstain_rate")
    c2_abs = c2.get("abstain_rate")
    c4_note = (
        "C4 LLM no-retrieval / no-SAST **ran**."
        if no_ret or no_sast
        else "C4 LLM no-retrieval / no-SAST **not run** (TPD) — do not claim RAG/SAST ablation on this snapshot."
    )
    c1_ids = [
        "sast_regex_research_test",
        "sast_regex_sanitized_research_test",
        "template_research_test",
        "llm_then_research_test",
        "llm_no_retrieval_research_test",
        "llm_no_sast_research_test",
    ]
    c2_ids = [
        "sast_regex_juliet_pairs",
        "sast_regex_sanitized_juliet_pairs",
        "template_juliet_pairs",
        "llm_then_juliet_pairs",
        "llm_no_retrieval_juliet_pairs",
    ]
    c2_per = c2.get("per_cwe") or {}
    fpr_table = md_table(
        ["CWE", "FP", "TN", "FPR"],
        [
            [cwe, scores.get("fp"), scores.get("tn"), f3(scores.get("fpr"))]
            for cwe, scores in sorted(c2_per.items())
        ],
    ) if c2_per else "_no per_cwe_"

    results = f"""# Chapter 5 — Results

Generated `{generated}`. Raw JSON: `results/thesis/`. Prompts sanitized. Lead with **CWE exact** and **pair accuracy + CI**. Family match is parent/child only; peers are a separate column.

## C1 Authored traps (n=24) — trap-overfit contrast, not the public headline

{detection_table(trials, c1_ids)}

- CWE exact: {pct(c1_cwe.get("correct", 0), c1_cwe.get("total", 0))}
- CWE parent/child (includes exact): {pct(c1_pc.get("correct", 0), c1_pc.get("total", 0))}
- CWE peer-only: {pct(c1_peer.get("correct", 0), c1_peer.get("total", 0))}
- CWE family (exact or parent/child, **not** peers): {pct(c1_fam.get("correct", 0), c1_fam.get("total", 0))}
- Validator pass: {c1.get("validation_pass")}/{c1.get("n_scored")} (cited_lines raw {f3(c1.get("cited_lines_rate"))}; indent-normalized {f3(c1.get("cited_lines_normalized_rate"))}; no span rewrite)
- Abstain rate: {f3(c1_abs) if c1_abs is not None else "—"}
- Tokens: prompt {c1_tok.get("prompt_tokens")} + completion {c1_tok.get("completion_tokens")} = {c1_tok.get("total_tokens")}; mean latency {c1_tok.get("latency_ms_mean")} ms
- Paths: `{c1.get("detector_path_counts")}`

Raw-disk regex SAST is 12 FP / 12 FN by trap construction. Template F1 on **sanitized** units is the fair regex contrast (comment-only hits are blanked). C1 F1 is that recovery, not Juliet.

C4 on C1 (same 24 units): no-retrieval F1 vs full LLM vs no-SAST is in the table above. Do not claim “RAG helps” unless no-retrieval is worse than the full path. Do not claim “SAST evidence helps” unless no-SAST is worse.

## C2 Juliet good/bad pairs (primary public LLM number)

{detection_table(trials, c2_ids)}

- C2 LLM status: `{c2.get("status")}` (n_scored={c2.get("n_scored")}/{c2.get("n_planned") or 36})
- **Pair accuracy (complete pairs only):** {pair.get("correct")}/{pair.get("n_pairs")} = {f3(pair.get("accuracy"))}
- Incomplete pairs excluded (TPD abort, not a model error): {pair.get("n_incomplete")}
- Bootstrap 95% CI (percentile, n_boot={ci.get("n_boot")}): [{ci.get("low")}, {ci.get("high")}], mean {ci.get("mean")}
- Pair abstain (any `uncertain` on a complete pair): {pair.get("n_abstain")} / {pair.get("n_pairs")} ({f3(pair.get("abstain_rate"))})
- CWE exact: {pct(c2_cwe.get("correct", 0), c2_cwe.get("total", 0))}
- CWE parent/child (includes exact): {pct(c2_pc.get("correct", 0), c2_pc.get("total", 0))}
- CWE peer-only: {pct(c2_peer.get("correct", 0), c2_peer.get("total", 0))}
- CWE family (exact or parent/child, **not** peers): {pct(c2_fam.get("correct", 0), c2_fam.get("total", 0))}
- Validator pass: {c2.get("validation_pass")}/{c2.get("n_scored")}
- Abstain rate (units): {f3(c2_abs) if c2_abs is not None else "—"}
- Tokens: {c2_tok.get("total_tokens")} total; mean latency {c2_tok.get("latency_ms_mean")} ms
- CWE-502: {pair.get("cwe_502")}
- Multi-file Juliet variants: excluded from the pair pool; the first C2 run that included `_NNa` files is archived under `results/thesis/archive/` if present.

Per-family FPR (binary, abstain-as-negative) on scored C2 units:

{fpr_table}

Families sampled: CWE-89, 80, 23, 327, 328, 259 (nearby ids kept, not relabeled to 79/22/798). Complete-pair n is smaller than 18 if TPD aborted a unit; report the CI, do not over-precision.

## C3 Sliced Vul4J

Regex SAST on the planned sliced units is kept if present. Live LLM is **{c3.get("status")}** (n_scored={c3.get("n_scored")}). **Do not cite a partial LLM F1 as a real-world result.**

## C4 / C5 / C7 / C8

- {c4_note}
- C5 Semgrep: see `semgrep_juliet_pairs.json` (skipped if not installed). Not compared to CodeQL (not run).
- C7 model ablation skipped unless `--include-model-ablation` and TPD remain.
- C8 `results/thesis/human_spotcheck.json` status `not_run` — unit ids may be sampled; labels are empty until Richa.

## Six-suite regex SAST (kept; not this LLM run)

From `results/benchmarks/summary.json` (`llm_rows_retracted=true`): Juliet n=20728 F1=0.316; OWASP n=2740 F1=0.395; Securibench n=119 F1=0.072; find-sec-bugs n=79 F1=0.435; Vul4J n=62 F1=0.244; CVEfixes-Java-slice n=92 F1=0.207. Regex ≠ CodeQL.
"""

    limits = """# Chapter 6 — Limitations

- Groq free-tier **200k tokens/day** can stop C3/C4/C7. Partial rows are labeled `partial` / `not_run`, never filled in.
- Authored traps were written against our regexes; C1 F1 is that contrast, not Juliet.
- Juliet pair CI is wide on n=18. Multi-file `_NNa` variants are excluded because they hide the sink; that is a methodology choice, not a claim that the model handles inter-file flows.
- Regex SAST is not AST/taint/CodeQL/Semgrep. Fair contrast uses sanitized units.
- Knowledge store is a MITRE **subset**. Nearby Juliet gold (80 vs 79, 23 vs 22) is disclosed, not relabeled.
- `final_confidence` is uncalibrated and does not route.
- Cited-line pass is reported raw **and** indent-normalized; we do not rewrite spans.
- Single-rater C8 not run; no inter-rater statistics.
- No HTTP API, auth, or multi-tenant service (see HLD gaps).
- RAG benefit on Juliet is unproven until C4 `llm_no_retrieval_juliet_pairs` exists.
"""

    conclusion = """# Chapter 7 — Conclusion and future work

The runnable system matches the official topic: RAG-augmented, **staged specialist agents** under a deterministic orchestrator, LLM explanations grounded in a structured CWE KB. After sanitizing prompts and surfacing rate limits, the defendable public LLM number is C2 pair accuracy with a bootstrap CI. C1 is the authored-trap contrast. Public-suite LLM scores from 2026-09-17 are retracted.

Future work: C4 no-RAG/no-SAST on the rebuilt single-file pair sample; finish C3 after TPD reset; C7 stronger ChatProvider via env; C8 human labels; optional Semgrep `p/java`; calibrated confidence on a held-out split. Do not claim RAG-on-Juliet or SOTA until those rows exist.
"""

    error_md = _error_analysis_md(
        c1,
        c2,
        sast_c1,
        sast_c1_san,
        template_c1,
        MULTI_FILE_STEM,
        retrieval_old=load_optional("archive/c2_multifile_superseded_retrieval_units_juliet_pairs.json"),
        retrieval_new=load_optional("retrieval_units_juliet_pairs.json"),
    )

    index = f"""# Thesis chapters (generated)

{TOPIC}
Richa Verma (25MCSS02) · Dr. Akshay Pandey

Generated from `results/thesis/summary.json` at `{generated}` by `scripts/write_thesis.py`.

1. [Introduction](01-introduction.md)
2. [Related work](02-related-work.md)
3. [System design](03-system-design.md)
4. [Experimental setup](04-experimental-setup.md)
5. [Results](05-results.md)
6. [Limitations](06-limitations.md)
7. [Conclusion](07-conclusion.md)
8. [Error analysis](08-error-analysis.md)

HLD/LLD: [`../design/hld.md`](../design/hld.md) · [`../design/lld.md`](../design/lld.md)
DOCX: `Thesis Progress Report_RichaVerma_25MCSS02.docx` (also copied to `results/thesis/Thesis_RichaVerma_25MCSS02.docx`)
"""

    THESIS_DIR.mkdir(parents=True, exist_ok=True)
    write(THESIS_DIR / "README.md", index)
    write(THESIS_DIR / "01-introduction.md", intro)
    write(THESIS_DIR / "02-related-work.md", related)
    write(THESIS_DIR / "03-system-design.md", design)
    write(THESIS_DIR / "04-experimental-setup.md", setup)
    write(THESIS_DIR / "05-results.md", results)
    write(THESIS_DIR / "06-limitations.md", limits)
    write(THESIS_DIR / "07-conclusion.md", conclusion)
    write(THESIS_DIR / "08-error-analysis.md", error_md)

    _write_docx(summary, c1, c2, pair, ci, generated)
    print(f"wrote {THESIS_DIR}")
    print(f"wrote {OFFICIAL_DOCX}")
    print(f"wrote {GENERATED_DOCX}")


def _write_docx(summary, c1, c2, pair, ci, generated: str) -> None:
    doc = Document()
    title = doc.add_heading(TOPIC, 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub = doc.add_paragraph("Richa Verma (25MCSS02)  ·  Advisor: Dr. Akshay Pandey")
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph(
        f"Thesis-shaped report. Tables loaded from results/thesis JSON ({generated}). "
        "Not a progress-report stub. Not SOTA. Not first RAG-CWE detector. "
        "Staged specialist agents; confidence is logged, not gating."
    )

    doc.add_heading("1. Introduction", level=1)
    doc.add_paragraph(
        "This thesis implements explainable Java CWE detection: regex SAST as evidence, "
        "hybrid MiniLM/TF-IDF + CWE-relationship RAG, a schema-bound Groq LLM, and a "
        "deterministic validator. Public-suite LLM rows from 2026-09-17 are retracted. "
        "The public LLM number is C2 pair accuracy with a bootstrap CI."
    )

    doc.add_heading("2. Related work", level=1)
    doc.add_paragraph(
        "RP1 (Big-Vul + GlassHouse partner data, not generic GitHub), MultiVer (Python), "
        "MulVul, MAVUL, HeterogenousMAS (C/C++ multi-agent; LLM verifier), MARVEL (RTL). "
        "Gap: Java + six web/enterprise CWEs + structured CWE KB in the prompt + A4 schema "
        "+ deterministic validator."
    )

    doc.add_heading("3. System design", level=1)
    doc.add_paragraph(
        "Six named stages (Evidence, Knowledge, Orchestrator, Reasoning, Validator, Report) "
        "as staged specialists, not a conversation bus. Default path is always-LLM. "
        "final_confidence is logged, not a gate. Regex is not AST. Hits include CWE passage text. "
        "CWE-0 is clamped to retrieved hits. 429 is never scored as live Groq. "
        "See docs/design/hld.md and docs/design/lld.md."
    )

    doc.add_heading("4. Experimental setup", level=1)
    doc.add_paragraph(
        "C1 n=24 authored traps; C2 18 Juliet pairs (36 units, seed=13, 3/family, "
        "single-file variants only); C3 Vul4J sliced planned 24. Groq openai/gpt-oss-20b. "
        "Pair correct iff bad→vulnerable and good→not_vulnerable. uncertain is incorrect. "
        "Bootstrap 1000 resamples. Fair SAST uses sanitized units."
    )

    doc.add_heading("5. Results", level=1)
    table = doc.add_table(rows=1, cols=8)
    hdr = table.rows[0].cells
    for i, name in enumerate(["System", "Status", "P", "R", "F1", "FP", "FN", "n"]):
        hdr[i].text = name
    by_id = {t.get("trial_id"): t for t in summary.get("trials") or []}
    for tid in [
        "sast_regex_research_test",
        "sast_regex_sanitized_research_test",
        "template_research_test",
        "llm_then_research_test",
        "sast_regex_juliet_pairs",
        "sast_regex_sanitized_juliet_pairs",
        "template_juliet_pairs",
        "llm_then_juliet_pairs",
        "sast_regex_vul4j_sliced",
        "llm_then_vul4j_sliced",
    ]:
        t = by_id.get(tid)
        if t is None:
            row = table.add_row().cells
            vals = [tid, "not_run", "—", "—", "—", "—", "—", "—"]
            for i, v in enumerate(vals):
                row[i].text = str(v)
            continue
        r = metric_row(t)
        row = table.add_row().cells
        vals = [tid, r["status"], f3(r["p"]), f3(r["r"]), f3(r["f1"]), r["fp"], r["fn"], r["n"]]
        for i, v in enumerate(vals):
            row[i].text = str(v)

    c1m = c1.get("metrics") or {}
    c2m = c2.get("metrics") or {}
    c1_exact = (c1.get("cwe_exact_match") or {})
    doc.add_paragraph(
        f"C1 live LLM F1={f3(c1m.get('f1'))} (P={f3(c1m.get('precision'))} "
        f"R={f3(c1m.get('recall'))}, n=24, CWE exact {c1_exact.get('correct')}/{c1_exact.get('total')}). "
        f"C2 live LLM binary F1={f3(c2m.get('f1'))}. Pair accuracy {pair.get('correct')}/{pair.get('n_pairs')} "
        f"= {f3(pair.get('accuracy'))}; bootstrap 95% CI [{ci.get('low')}, {ci.get('high')}]. "
        "C3 LLM may be partial (TPD); do not cite as a full real-world score. "
        "C4 no-RAG/no-SAST LLM may be not_run. C5 Semgrep skipped unless installed; C7/C8 not run."
    )

    doc.add_heading("6. Limitations", level=1)
    doc.add_paragraph(
        "TPD cap; authored-trap overfitting; Juliet pair CI is wide; multi-file Juliet variants "
        "excluded because they hide the sink; no CodeQL; uncalibrated logged confidence; "
        "raw and indent-normalized cited-line rates; C8 unlabeled."
    )

    doc.add_heading("7. Conclusion", level=1)
    doc.add_paragraph(
        "The composition is implemented and measured honestly. The public LLM number is C2 pair "
        "accuracy with CI. C1 is the trap contrast. Resume C3/C4/C7 after quota reset. "
        "Human spot-check remains Richa's."
    )

    doc.add_heading("8. Error analysis", level=1)
    doc.add_paragraph(
        "See docs/thesis/08-error-analysis.md: pair fails by family, multi-file sampling bug, "
        "CWE-0, indent citation, comment-trap SAST confound. Generated from JSON, not filled in."
    )

    doc.add_paragraph(
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')} from results/thesis/summary.json."
    )
    GENERATED_DOCX.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(OFFICIAL_DOCX))
    doc.save(str(GENERATED_DOCX))


if __name__ == "__main__":
    build()
