"""Reproducible research evaluation on the authored expanded Java corpus."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cwe_vuln.config import MissingLLMKeyError, MISSING_LLM_KEY_MESSAGE, repo_root, settings
from cwe_vuln.dataset import SeedUnit, load_research_corpus, load_seed
from cwe_vuln.models.metrics import binary_metrics
from cwe_vuln.orchestrator import Pipeline
from cwe_vuln.reasoner import LLMReasoner, TemplateReasoner
from cwe_vuln.retrieval import HybridRetriever, evaluate_retriever, load_retrieval_queries
from cwe_vuln.sast import RegexEvidenceExtractor, detect
from cwe_vuln.validator import ResultValidator

DISCLAIMER = (
    "authored corpus — not a public benchmark. Metrics are computed only on "
    "the authored Java units and labeled queries in this repository. Not Juliet, "
    "OWASP Benchmark, or Big-Vul."
)

FALLBACK_MODELS = (
    "openai/gpt-oss-20b",
    "llama-3.3-70b-versatile",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "gemma2-9b-it",
)


def experiments_dir(root: Path | None = None) -> Path:
    path = (root or repo_root()) / "results" / "experiments"
    path.mkdir(parents=True, exist_ok=True)
    return path


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact(text: str) -> str:
    return re.sub(r"gsk_[A-Za-z0-9]+", "gsk_REDACTED", text)


def write_trial(payload: dict[str, Any], output_dir: Path) -> Path:
    trial_id = str(payload["trial_id"])
    path = output_dir / f"{trial_id}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _per_cwe(units: list[SeedUnit], y_pred: list[bool]) -> dict[str, dict[str, int | float]]:
    grouped: dict[str, list[tuple[SeedUnit, bool]]] = defaultdict(list)
    for unit, pred in zip(units, y_pred, strict=True):
        grouped[unit.cwe_id].append((unit, pred))
    out: dict[str, dict[str, int | float]] = {}
    for cwe_id, pairs in grouped.items():
        scores = binary_metrics([item.is_vulnerable for item, _ in pairs], [pred for _, pred in pairs])
        out[cwe_id] = scores.as_dict()
    return out


def _confusion(units: list[SeedUnit], y_pred: list[bool], sast_hits: list[bool], reasoner: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for unit, pred, sast in zip(units, y_pred, sast_hits, strict=True):
        why = _why(unit, pred, sast, reasoner)
        if why == "ok":
            continue
        rows.append(
            {
                "unit_id": unit.unit_id,
                "cwe_id": unit.cwe_id,
                "trap_type": unit.trap_type,
                "true_label": unit.label,
                "predicted": "vulnerable" if pred else "not_vulnerable",
                "sast_hit": sast,
                "why": why,
            }
        )
    return rows


def _why(unit: SeedUnit, predicted_vuln: bool, sast_hit: bool, reasoner: str) -> str:
    gold = unit.is_vulnerable
    if gold == predicted_vuln:
        return "ok"
    if predicted_vuln and not gold:
        if sast_hit:
            return "sast_false_positive" if reasoner == "sast" else "follows_sast_false_positive"
        return "llm_overclaim"
    if sast_hit:
        return "llm_miss_despite_sast"
    return "sast_miss"


def _detection_trial(
    trial_id: str,
    split: str,
    units: list[SeedUnit],
    y_pred: list[bool],
    config: dict[str, Any],
    notes: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    sast_hits = [detect(unit).is_vulnerable for unit in units]
    y_true = [unit.is_vulnerable for unit in units]
    scores = binary_metrics(y_true, y_pred)
    reasoner = str(config.get("reasoner", "sast"))
    payload: dict[str, Any] = {
        "trial_id": trial_id,
        "date": utc_now(),
        "suite": config.get("suite", "research"),
        "split": split,
        "n_units": len(units),
        "evaluation_scope": "authored_corpus_not_a_public_benchmark",
        "disclaimer": DISCLAIMER,
        "status": "ok",
        "config": config,
        "metrics": scores.as_dict(),
        "per_cwe": _per_cwe(units, y_pred),
        "confusion": _confusion(units, y_pred, sast_hits, reasoner),
        "notes": notes,
        "error": None,
    }
    if extra:
        payload.update(extra)
    return payload


def trial_sast(units: list[SeedUnit], split: str, suite: str) -> dict[str, Any]:
    y_pred = [detect(unit).is_vulnerable for unit in units]
    return _detection_trial(
        trial_id=f"sast_regex_{split}",
        split=split,
        units=units,
        y_pred=y_pred,
        config={"suite": suite, "reasoner": "sast", "backend": "regex"},
        notes="Regex SAST only. On research_test this should be imperfect by construction.",
    )


def trial_pipeline(
    trial_id: str,
    units: list[SeedUnit],
    split: str,
    suite: str,
    pipeline: Pipeline,
    notes: str,
) -> dict[str, Any]:
    rows = []
    y_pred: list[bool] = []
    errors: list[str] = []
    for unit in units:
        try:
            row = pipeline.run(unit)
            rows.append(row)
            y_pred.append(row.result.decision == "vulnerable")
        except Exception as exc:
            errors.append(redact(f"{unit.unit_id}: {exc}"))
            y_pred.append(False)
            rows.append(None)
    validator_pass = sum(1 for row in rows if row is not None and row.report.passed)
    cited_ok = 0
    cited_n = 0
    for row in rows:
        if row is None:
            continue
        for check in row.report.checks:
            if check.name != "cited_lines":
                continue
            cited_n += 1
            if check.passed:
                cited_ok += 1
    disagreement = 0
    for row in rows:
        if row is None:
            continue
        if any(item.name == "sast_disagreement" for item in row.report.warnings):
            disagreement += 1
    extra = {
        "validation_pass": validator_pass,
        "validation_pass_rate": (validator_pass / len(units)) if units else 0.0,
        "cited_lines_grounded": cited_ok,
        "cited_lines_n": cited_n,
        "cited_lines_rate": (cited_ok / cited_n) if cited_n else 0.0,
        "sast_disagreement": disagreement,
        "sast_disagreement_rate": (disagreement / len(units)) if units else 0.0,
        "detector_path_counts": _counts(getattr(row, "path", None) for row in rows if row is not None),
        "reasoner_counts": _counts(getattr(row, "reasoner", None) for row in rows if row is not None),
        "embedder": getattr(pipeline.retriever, "embedder_name", "unknown"),
        "unit_decisions": [
            {
                "unit_id": unit.unit_id,
                "decision": None if row is None else row.result.decision,
                "path": None if row is None else row.path,
                "reasoner": None if row is None else row.reasoner,
                "validator_passed": None if row is None else row.report.passed,
                "sast_disagreement": None
                if row is None
                else any(item.name == "sast_disagreement" for item in row.report.warnings),
            }
            for unit, row in zip(units, rows, strict=True)
        ],
    }
    payload = _detection_trial(
        trial_id=trial_id,
        split=split,
        units=units,
        y_pred=y_pred,
        config={
            "suite": suite,
            "reasoner": "template" if pipeline.llm_reasoner is None else "llm",
            "skip_llm_when_sast_hits": pipeline.skip_llm_when_sast_hits,
            "use_llm_if_available": pipeline.use_llm_if_available,
            "model": getattr(pipeline.llm_reasoner, "model", None),
        },
        notes=notes if not errors else notes + " Partial unit errors: " + "; ".join(errors[:8]),
        extra=extra,
    )
    if errors and all(row is None for row in rows):
        payload["status"] = "failed"
        payload["error"] = redact("; ".join(errors[:5]))
    elif errors:
        payload["status"] = "partial"
        payload["error"] = redact("; ".join(errors[:5]))
    return payload


def trial_retrieval(retriever: HybridRetriever, suite: str) -> list[dict[str, Any]]:
    files = ("labeled_queries.jsonl", "research_queries.jsonl")
    queries = load_retrieval_queries(files=files)
    report = evaluate_retriever(retriever, queries, k_values=(1, 3, 5, 10))
    report["evaluation_scope"] = "authored_corpus_not_a_public_benchmark"
    report["disclaimer"] = DISCLAIMER
    report["n_queries"] = len(queries)
    report["query_files"] = list(files)
    trials: list[dict[str, Any]] = []
    systems = report["systems"]
    mapping = {
        "lexical_tfidf": "retrieval_tfidf_expanded",
        "neural": "retrieval_minilm_expanded",
        "hybrid_rrf": "retrieval_hybrid_rrf_expanded",
    }
    for system_key, trial_id in mapping.items():
        scores = systems[system_key]
        trials.append(
            {
                "trial_id": trial_id,
                "date": utc_now(),
                "suite": suite,
                "split": "expanded_queries",
                "evaluation_scope": "authored_corpus_not_a_public_benchmark",
                "disclaimer": DISCLAIMER,
                "status": "ok" if retriever.embedder_name != "tfidf_fallback" or system_key == "lexical_tfidf" else "ok_with_fallback",
                "config": {
                    "system": system_key,
                    "embedder": retriever.embedder_name,
                    "top_k": [3, 5, 10],
                    "n_queries": len(queries),
                },
                "metrics": scores,
                "notes": (
                    "Expanded labeled queries: 18 assignment queries plus research unit notes "
                    f"and NL queries ({len(queries)} total). MiniLM missing → neural=tfidf_fallback."
                    if retriever.embedder_name != "minilm" and system_key == "neural"
                    else "Expanded authored queries — not a public benchmark."
                ),
                "error": None,
                "embedder": retriever.embedder_name,
            }
        )
    trials.append(
        {
            "trial_id": "retrieval_expanded_all_systems",
            "date": utc_now(),
            "suite": suite,
            "split": "expanded_queries",
            "evaluation_scope": "authored_corpus_not_a_public_benchmark",
            "disclaimer": DISCLAIMER,
            "status": "ok",
            "config": {"embedder": retriever.embedder_name, "k_values": [1, 3, 5, 10], "n_queries": len(queries)},
            "metrics": systems,
            "notes": DISCLAIMER,
            "error": None,
            "report": {
                "embedder": report.get("embedder"),
                "n_queries": report["n_queries"],
                "k_values": report["k_values"],
                "systems": systems,
            },
        }
    )
    return trials


def _counts(values) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        if not value:
            continue
        counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def _make_pipeline(
    retriever: HybridRetriever,
    llm: LLMReasoner | None,
    skip_llm_when_sast_hits: bool,
    use_llm: bool,
) -> Pipeline:
    return Pipeline(
        extractor=RegexEvidenceExtractor(),
        retriever=retriever,
        reasoner=TemplateReasoner(),
        validator=ResultValidator(),
        llm_reasoner=llm if use_llm else None,
        skip_llm_when_sast_hits=skip_llm_when_sast_hits,
        use_llm_if_available=use_llm,
    )


def _build_llm(model: str) -> LLMReasoner | None:
    key = settings.llm_api_key()
    if not key:
        return None
    return LLMReasoner(api_key=key, model=model)


def _failed_trial(trial_id: str, split: str, suite: str, notes: str, error: str, config: dict[str, Any]) -> dict[str, Any]:
    return {
        "trial_id": trial_id,
        "date": utc_now(),
        "suite": suite,
        "split": split,
        "evaluation_scope": "authored_corpus_not_a_public_benchmark",
        "disclaimer": DISCLAIMER,
        "status": "failed",
        "config": config,
        "metrics": None,
        "notes": notes,
        "error": redact(error),
    }


def _candidate_models() -> list[str]:
    ordered: list[str] = []
    for name in (settings.llm_model(), *FALLBACK_MODELS):
        if name and name not in ordered:
            ordered.append(name)
    return ordered


def run_research_suite(ablation: str = "none") -> list[dict[str, Any]]:
    if ablation != "template" and not settings.llm_api_key():
        raise MissingLLMKeyError(MISSING_LLM_KEY_MESSAGE)

    units = load_research_corpus(split="research_test")
    retriever = HybridRetriever.load(allow_download=True)
    trials: list[dict[str, Any]] = [
        trial_sast(units, "research_test", "research"),
        trial_pipeline(
            "template_skip_llm_research_test",
            units,
            "research_test",
            "research",
            _make_pipeline(retriever, None, skip_llm_when_sast_hits=True, use_llm=False),
            notes="Ablation: TemplateReasoner, no LLM. Decisions follow regex evidence. Not the system of record.",
        ),
    ]
    trials.extend(trial_retrieval(retriever, "research"))

    if ablation == "template":
        return trials

    llm, model_notes = _llm_with_fallback()
    if llm is None:
        trials.append(
            _failed_trial(
                "llm_then_research_test",
                "research_test",
                "research",
                model_notes,
                model_notes,
                {"reasoner": "llm", "candidates": _candidate_models()},
            )
        )
        return trials

    then_pipe = _make_pipeline(retriever, llm, skip_llm_when_sast_hits=False, use_llm=True)
    trials.append(
        trial_pipeline(
            "llm_then_research_test",
            units,
            "research_test",
            "research",
            then_pipe,
            notes="System of record: live Groq LLMReasoner grounded in code + SAST evidence + hybrid CWE hits. "
            + model_notes,
        )
    )
    seed_test = load_seed(split="test")
    time.sleep(1)
    trials.append(
        trial_pipeline(
            "llm_then_seed_test",
            seed_test,
            "test",
            "seed",
            then_pipe,
            notes="Live Groq on the assignment seed test split (n=4). seed-only — not a benchmark. " + model_notes,
        )
    )
    if ablation == "skip-llm":
        time.sleep(1)
        skip_pipe = _make_pipeline(retriever, llm, skip_llm_when_sast_hits=True, use_llm=True)
        trials.append(
            trial_pipeline(
                "llm_skip_when_sast_research_test",
                units,
                "research_test",
                "research",
                skip_pipe,
                notes="Ablation cost path skip_llm: SAST hits use template; no-hit units use LLM. " + model_notes,
            )
        )
    return trials


def _llm_with_fallback() -> tuple[LLMReasoner | None, str]:
    notes: list[str] = []
    for model in _candidate_models():
        reasoner = _build_llm(model)
        if reasoner is None:
            return None, "missing_api_key"
        try:
            reasoner._complete(
                [
                    {"role": "system", "content": "Return JSON only."},
                    {"role": "user", "content": '{"ping": true}'},
                ]
            )
            notes.append(f"probe_ok model={model}")
            return reasoner, " ".join(notes)
        except Exception as exc:
            text = redact(str(exc))
            notes.append(f"probe_failed model={model}: {text}")
            lowered = text.lower()
            if "404" in text or "not_found" in lowered or "does not exist" in lowered:
                continue
            if "429" in text or "rate limit" in lowered:
                time.sleep(8)
                continue
            return reasoner, " ".join(notes) + " (using model after probe warning)"
    return None, " ".join(notes) or "all_models_failed"


def run_seed_suite() -> list[dict[str, Any]]:
    units = load_seed()
    return [trial_sast(units, "seed_all", "seed")]


def write_summary(trials: list[dict[str, Any]], root: Path | None = None, summary_dir: Path | None = None) -> tuple[Path, Path]:
    dest = summary_dir if summary_dir is not None else ((root or repo_root()) / "results")
    dest.mkdir(parents=True, exist_ok=True)
    detection = [
        item
        for item in trials
        if item.get("status") == "ok"
        and isinstance(item.get("metrics"), dict)
        and "precision" in item["metrics"]
    ]
    order = (
        "sast_regex_research_test",
        "template_skip_llm_research_test",
        "llm_then_research_test",
        "llm_then_seed_test",
        "llm_skip_when_sast_research_test",
    )
    detection.sort(key=lambda item: order.index(item["trial_id"]) if item["trial_id"] in order else 99)
    retrieval = [
        item
        for item in trials
        if str(item.get("trial_id", "")).startswith("retrieval_") and item.get("status") in {"ok", "ok_with_fallback"}
    ]
    retrieval.sort(key=lambda item: str(item.get("trial_id")))
    summary = {
        "generated_at": utc_now(),
        "evaluation_scope": "authored_corpus_not_a_public_benchmark",
        "disclaimer": DISCLAIMER,
        "research_split": {
            "seed_n": 12,
            "research_test_n": 24,
            "corpus_n": 36,
        },
        "trials": [
            {
                "trial_id": item["trial_id"],
                "status": item.get("status"),
                "split": item.get("split"),
                "metrics": item.get("metrics"),
                "notes": item.get("notes"),
                "error": item.get("error"),
            }
            for item in trials
        ],
        "detection_table": [
            {
                "system": item["trial_id"],
                "precision": item["metrics"]["precision"],
                "recall": item["metrics"]["recall"],
                "f1": item["metrics"]["f1"],
                "fp": item["metrics"]["fp"],
                "fn": item["metrics"]["fn"],
                "n": item["metrics"]["support"],
                "validation_pass": item.get("validation_pass"),
                "validation_pass_rate": item.get("validation_pass_rate"),
            }
            for item in detection
        ],
        "retrieval_table": [
            {
                "system": item["trial_id"],
                "metrics": item.get("metrics"),
                "embedder": item.get("embedder") or item.get("config", {}).get("embedder"),
            }
            for item in retrieval
            if item["trial_id"] != "retrieval_expanded_all_systems"
        ],
    }
    json_path = dest / "research-eval-summary.json"
    json_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    md_path = dest / "research-eval-summary.md"
    md_path.write_text(_summary_markdown(summary), encoding="utf-8")
    return json_path, md_path


def _summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Research evaluation summary",
        "",
        "**authored corpus — not a public benchmark.**",
        "",
        summary["disclaimer"],
        "",
        f"- Generated: `{summary['generated_at']}`",
        f"- Seed n=12 (8/4 assignment split) · research test n=24 · corpus n=36",
        "",
        "## Detection (research trials)",
        "",
        "| System | Precision | Recall | F1 | FP | FN | n | Validator |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary["detection_table"]:
        val = row.get("validation_pass")
        n = row["n"]
        val_cell = "—" if val is None else f"{val}/{n}"
        lines.append(
            f"| {row['system']} | {row['precision']:.3f} | {row['recall']:.3f} | "
            f"{row['f1']:.3f} | {row['fp']} | {row['fn']} | {n} | {val_cell} |"
        )
    lines.extend(
        [
            "",
            "## Retrieval (expanded authored queries)",
            "",
            "| System | R@1 | R@3 | R@5 | R@10 | MRR |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in summary["retrieval_table"]:
        metrics = row.get("metrics") or {}
        if "recall@1" not in metrics:
            continue
        lines.append(
            f"| {row['system']} | {metrics.get('recall@1', 0):.3f} | {metrics.get('recall@3', 0):.3f} | "
            f"{metrics.get('recall@5', 0):.3f} | {metrics.get('recall@10', 0):.3f} | {metrics.get('mrr', 0):.3f} |"
        )
    lines.extend(["", "## Trial log", ""])
    for item in summary["trials"]:
        err = f" error={item['error']}" if item.get("error") else ""
        lines.append(f"- `{item['trial_id']}` status={item['status']}{err}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run authored-corpus research evaluation trials.")
    parser.add_argument("--suite", choices=["research", "seed", "all"], default="research")
    parser.add_argument(
        "--ablation",
        choices=["none", "template", "skip-llm"],
        default="none",
        help="none = live Groq (default). template = SAST/template contrast only. skip-llm = cost-path ablation.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Alias for --ablation template (paper comparison; not the system of record).",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Deprecated alias for --ablation template.",
    )
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    ablation = args.ablation
    if args.offline or args.skip_llm:
        ablation = "template"

    out = args.output_dir or experiments_dir()
    out.mkdir(parents=True, exist_ok=True)
    trials: list[dict[str, Any]] = []
    try:
        if args.suite in {"research", "all"}:
            trials.extend(run_research_suite(ablation=ablation))
        if args.suite in {"seed", "all"}:
            trials.extend(run_seed_suite())
    except MissingLLMKeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    for trial in trials:
        path = write_trial(trial, out)
        print(f"wrote {path} status={trial.get('status')}")
    known = {item["trial_id"] for item in trials}
    extras: list[dict[str, Any]] = []
    for path in sorted(out.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        trial_id = payload.get("trial_id")
        if trial_id and trial_id not in known:
            extras.append(payload)
            known.add(trial_id)
    json_path, md_path = write_summary(
        trials + extras,
        summary_dir=args.output_dir if args.output_dir is not None else None,
    )
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    print(DISCLAIMER)
    failed = [item for item in trials if item.get("status") == "failed"]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
