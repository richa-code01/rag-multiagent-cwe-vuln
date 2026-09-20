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

from cwe_vuln.config import MissingLLMKeyError, repo_root, settings
from cwe_vuln.llm import OpenAICompatProvider, fallback_models, missing_key_message
from cwe_vuln.dataset import SeedUnit, load_research_corpus, load_seed
from cwe_vuln.dataset.sanitize import find_gold_tokens, opaque_unit_id, sanitize_unit
from cwe_vuln.knowledge import CWEKnowledgeBase
from cwe_vuln.dataset.common import (
    DEFAULT_SUITE_SAMPLE_N,
    SuiteError,
    load_sample_units as load_suite_sample_units,
    stratified_suite_sample,
    write_sample_manifest as write_suite_sample_manifest,
)
from cwe_vuln.dataset.juliet import (
    DEFAULT_PER_CWE,
    JULIET_VERSION,
    LLM_SAMPLE_CWES,
    SAMPLE_SEED,
    JulietError,
    ensure_juliet,
    load_juliet_units,
    load_sample_units,
    mapping_notes,
    provenance_path,
    sample_manifest_path,
    stratified_sample,
    write_sample_manifest,
)
from cwe_vuln.dataset.registry import (
    LLM_SUITE_NAMES,
    SAST_SUITE_NAMES,
    SUITES,
    resolve_suite,
)
from cwe_vuln.models.metrics import binary_metrics
from cwe_vuln.orchestrator import Pipeline
from cwe_vuln.reasoner import LLMReasoner, TemplateReasoner
from cwe_vuln.retrieval import HybridRetriever, evaluate_retriever, load_retrieval_queries
from cwe_vuln.sast import detect

DISCLAIMER = (
    "authored corpus — not a public benchmark. Metrics are computed only on "
    "the authored Java units and labeled queries in this repository. Not Juliet, "
    "OWASP Benchmark, or Big-Vul."
)

JULIET_DISCLAIMER = (
    "Juliet Java public-benchmark subset. Not the authored 36-unit research table. "
    "LLM scores are on a stratified sample only unless n equals the ingested SAST set. "
    "Nearby CWE folders keep their Juliet ids (no silent relabel to 79/22/798/327)."
)

# Fallback model list is owned by the selected provider preset (see cwe_vuln.llm.spec).
# Groq (default): openai/gpt-oss-20b, openai/gpt-oss-120b, qwen/qwen3.8-27b.

# Set by main(); raw LLM responses land in <output_dir>/raw_llm/<trial_id>/*.json.
# Gitignored. None disables capture (unit tests call trial_pipeline directly).
RAW_LLM_DIR: Path | None = None
# When True, trial_pipeline reuses raw_llm/<trial_id>/<opaque_id>.json instead of
# calling the provider. Used by --resume so a crashed TPD run does not re-bill Groq.
REPLAY_RAW_LLM = False


def experiments_dir(root: Path | None = None) -> Path:
    path = (root or repo_root()) / "results" / "experiments"
    path.mkdir(parents=True, exist_ok=True)
    return path


def benchmarks_results_dir(root: Path | None = None) -> Path:
    path = (root or repo_root()) / "results" / "benchmarks"
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


def load_ok_trial(output_dir: Path, trial_id: str) -> dict[str, Any] | None:
    """Return an on-disk trial with status=ok, else None. Used by --resume."""
    path = output_dir / f"{trial_id}.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if payload.get("status") == "ok":
        return payload
    return None


def trial_token_count(trial: dict[str, Any]) -> int:
    usage = trial.get("token_usage") or {}
    return int(usage.get("total_tokens") or 0)


def skipped_trial(trial_id: str, reason: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "trial_id": trial_id,
        "date": utc_now(),
        "status": "skipped",
        "metrics": None,
        "notes": reason,
        "error": None,
    }
    payload.update(extra)
    return payload


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


def trial_sast(
    units: list[SeedUnit],
    split: str,
    suite: str,
    *,
    sanitized: bool = False,
) -> dict[str, Any]:
    if sanitized:
        y_pred = [detect(sanitize_unit(unit)).is_vulnerable for unit in units]
        trial_id = f"sast_regex_sanitized_{split}"
        notes = (
            "Regex SAST on sanitized units (same input as template/LLM). "
            "Comment-only regex hits disappear when comments are blanked."
        )
        extra: dict[str, Any] = {"sast_input": "sanitized"}
    else:
        y_pred = [detect(unit).is_vulnerable for unit in units]
        trial_id = f"sast_regex_{split}"
        notes = (
            "Regex SAST on original units (raw disk). Not the fair LLM contrast; "
            f"see sast_regex_sanitized_{split} for the apples-to-apples row."
        )
        extra = {"sast_input": "raw_disk"}
    return _detection_trial(
        trial_id=trial_id,
        split=split,
        units=units,
        y_pred=y_pred,
        config={"suite": suite, "reasoner": "sast", "backend": "regex", "sast_input": extra["sast_input"]},
        notes=notes,
        extra=extra,
    )


def trial_pipeline(
    trial_id: str,
    units: list[SeedUnit],
    split: str,
    suite: str,
    pipeline: Pipeline,
    notes: str,
    *,
    delay_seconds: float = 0.0,
    stop_on_rate_limit: bool = False,
    evaluation_scope: str | None = None,
    disclaimer: str | None = None,
) -> dict[str, Any]:
    """Run the pipeline on sanitized prompt copies; score against original gold.

    Every unit is sanitized before the LLM sees it (opaque id, neutral path,
    FLAW/FIX comments blanked, bad/good identifiers renamed). Scoring uses the
    original unit labels. Units that error (non-rate-limit) are excluded from
    scoring and listed under failed_units — never silently scored as benign.
    """
    kb = CWEKnowledgeBase.load()
    rows: list[Any] = []
    y_pred: list[bool] = []
    errors: list[str] = []
    used: list[SeedUnit] = []
    failed: list[dict[str, str]] = []
    prompt_leaks: list[str] = []
    rate_limited = False
    skipped = 0
    replayed = 0
    n_planned = len(units)
    for index, unit in enumerate(units):
        cached = _load_raw_llm(trial_id, unit) if REPLAY_RAW_LLM else None
        if delay_seconds and index and cached is None:
            time.sleep(delay_seconds)
        prompt_unit = sanitize_unit(unit)
        try:
            row = _run_unit(pipeline, prompt_unit, cached)
        except Exception as exc:
            text = redact(f"{unit.unit_id}: {exc}")
            if stop_on_rate_limit and _is_rate_limit(text):
                row = _retry_after_backoff(pipeline, prompt_unit)
                if row is None:
                    rate_limited = True
                    errors.append(text)
                    skipped = n_planned - index
                    break
            else:
                errors.append(text)
                failed.append({"unit_id": unit.unit_id, "error": text})
                continue
        if cached is not None:
            replayed += 1
        rows.append(row)
        y_pred.append(row.result.decision == "vulnerable")
        used.append(unit)
        leaks = _prompt_gold_tokens(pipeline)
        if leaks:
            prompt_leaks.append(f"{unit.unit_id}:{','.join(leaks)}")
        if cached is None:
            _write_raw_llm(trial_id, unit, pipeline)
        if RAW_LLM_DIR is not None:
            kind = "replay" if cached is not None else "live"
            print(f"{trial_id} {index + 1}/{n_planned} {kind} {unit.unit_id}", flush=True)
    n_scored = len(used)
    validator_pass = sum(1 for row in rows if row.report.passed)
    cited_ok = cited_n = 0
    cited_norm_ok = cited_norm_n = 0
    for row in rows:
        for check in row.report.checks:
            if check.name == "cited_lines":
                cited_n += 1
                if check.passed:
                    cited_ok += 1
            elif check.name == "cited_lines_normalized":
                cited_norm_n += 1
                if check.passed:
                    cited_norm_ok += 1
    disagreement = 0
    for row in rows:
        if any(item.name == "sast_disagreement" for item in row.report.warnings):
            disagreement += 1
    cwe_exact, cwe_parent_child, cwe_peer, cwe_family = _cwe_match(rows, used, kb)
    decisions = [row.result.decision for row in rows]
    n_abstain = sum(1 for item in decisions if item == "uncertain")
    y_true_all = [unit.is_vulnerable for unit in used]
    y_true_ex = [truth for truth, decision in zip(y_true_all, decisions, strict=True) if decision != "uncertain"]
    y_pred_ex = [decision == "vulnerable" for decision in decisions if decision != "uncertain"]
    exclude_metrics = binary_metrics(y_true_ex, y_pred_ex).as_dict()
    n_clamped = sum(1 for row in rows if getattr(row, "cwe_clamped_from", None))
    extra = {
        "validation_pass": validator_pass,
        "validation_pass_rate": (validator_pass / n_scored) if n_scored else 0.0,
        "cited_lines_grounded": cited_ok,
        "cited_lines_n": cited_n,
        "cited_lines_rate": (cited_ok / cited_n) if cited_n else 0.0,
        "cited_lines_note": "raw pass rate; no span substitution is applied to LLM citations",
        "cited_lines_normalized_grounded": cited_norm_ok,
        "cited_lines_normalized_n": cited_norm_n,
        "cited_lines_normalized_rate": (cited_norm_ok / cited_norm_n) if cited_norm_n else 0.0,
        "sast_disagreement": disagreement,
        "sast_disagreement_rate": (disagreement / n_scored) if n_scored else 0.0,
        "cwe_exact_match": cwe_exact,
        "cwe_parent_child_match": cwe_parent_child,
        "cwe_peer_match": cwe_peer,
        "cwe_family_match": cwe_family,
        "cwe_family_definition": "exact or parent/child; peers are a separate column",
        "cwe_clamped_n": n_clamped,
        "cwe_clamped_rate": (n_clamped / n_scored) if n_scored else 0.0,
        "abstain_n": n_abstain,
        "abstain_rate": (n_abstain / n_scored) if n_scored else 0.0,
        "metrics_exclude_abstain": exclude_metrics,
        "uncertain_policy": (
            "Binary `metrics` treat uncertain as not_vulnerable (abstain-as-negative). "
            "`metrics_exclude_abstain` drops those units. Pair accuracy treats uncertain as incorrect."
        ),
        "detector_path_counts": _counts(row.path for row in rows),
        "reasoner_counts": _counts(row.reasoner for row in rows),
        "embedder": getattr(pipeline.retriever, "embedder_name", "unknown"),
        "prompt_sanitized": True,
        "prompt_audit_leaks": prompt_leaks,
        "failed_units": failed,
        "token_usage": _token_usage(rows),
        "unit_decisions": [
            _unit_decision(unit, row, kb)
            for unit, row in zip(used, rows, strict=True)
        ],
        "n_planned": n_planned,
        "n_scored": n_scored,
        "replayed_n": replayed,
        "rate_limited": rate_limited,
        "skipped_due_to_rate_limit": skipped,
    }
    payload = _detection_trial(
        trial_id=trial_id,
        split=split,
        units=used,
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
    if not used:
        payload["status"] = "failed"
        payload["error"] = redact("; ".join(errors[:5]) or "no units scored")
    elif errors or failed:
        payload["status"] = "partial"
        payload["error"] = redact("; ".join(errors[:5]) or f"{len(failed)} unit errors")
    if rate_limited:
        payload["status"] = "partial" if used else "failed"
        payload["error"] = redact("; ".join(errors[:5]) or "rate_limited")
    if evaluation_scope:
        payload["evaluation_scope"] = evaluation_scope
    if disclaimer:
        payload["disclaimer"] = disclaimer
    return payload


def _retry_after_backoff(pipeline: Pipeline, prompt_unit: SeedUnit) -> Any | None:
    """Backoff on 429: 12s, 30s, 60s. Returns the row or None if still limited."""
    for wait in (12, 30, 60):
        time.sleep(wait)
        try:
            return pipeline.run(prompt_unit)
        except Exception as retry_exc:
            if not _is_rate_limit(redact(str(retry_exc))):
                return None
    return None


def _prompt_gold_tokens(pipeline: Pipeline) -> list[str]:
    """Tripwire: gold tokens found in the rendered prompt (should be empty)."""
    reasoner = pipeline.llm_reasoner
    prompt = getattr(reasoner, "last_prompt", None) if reasoner is not None else None
    if prompt is None:
        return []
    return find_gold_tokens(prompt.text)


def _write_raw_llm(trial_id: str, unit: SeedUnit, pipeline: Pipeline) -> None:
    """Persist the raw LLM response + diagnostics for the error taxonomy."""
    if RAW_LLM_DIR is None:
        return
    reasoner = pipeline.llm_reasoner
    if reasoner is None or not str(getattr(reasoner, "last_backend", "")).startswith("llm"):
        return
    prompt = getattr(reasoner, "last_prompt", None)
    dest = RAW_LLM_DIR / trial_id
    dest.mkdir(parents=True, exist_ok=True)
    prompt_id = opaque_unit_id(unit.unit_id)
    payload = {
        "unit_id": unit.unit_id,
        "prompt_id": prompt_id,
        "model": getattr(reasoner, "model", None),
        "backend": getattr(reasoner, "last_backend", None),
        "n_attempts": getattr(reasoner, "n_attempts", None),
        "fallback_reason": getattr(reasoner, "fallback_reason", None),
        "errors": getattr(reasoner, "last_errors", None),
        "usage": getattr(reasoner, "last_usage", None),
        "latency_ms": getattr(reasoner, "last_latency_ms", None),
        "finish_reason": getattr(reasoner, "last_finish_reason", None),
        "raw_response": getattr(reasoner, "last_raw", ""),
        "prompt_text": prompt.text if prompt is not None else None,
    }
    path = dest / f"{prompt_id}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _load_raw_llm(trial_id: str, unit: SeedUnit) -> dict[str, Any] | None:
    """Return a persisted Groq response for this unit, or None."""
    if RAW_LLM_DIR is None:
        return None
    path = RAW_LLM_DIR / trial_id / f"{opaque_unit_id(unit.unit_id)}.json"
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not (payload.get("raw_response") or "").strip():
        return None
    return payload


def _llm_backend(pipeline: Pipeline) -> Any | None:
    reasoner = pipeline.llm_reasoner
    if reasoner is None:
        return None
    return getattr(reasoner, "backend", reasoner)


def _run_unit(pipeline: Pipeline, prompt_unit: SeedUnit, cached: dict[str, Any] | None) -> Any:
    """Run the pipeline, optionally substituting a persisted LLM completion."""
    backend = _llm_backend(pipeline)
    if cached is None or backend is None or not hasattr(backend, "_complete"):
        return pipeline.run(prompt_unit)
    original = backend._complete

    def _cached(_messages: list[dict[str, str]], _payload: dict[str, Any] = cached) -> str:
        usage = _payload.get("usage") or {}
        backend.last_usage = {
            "prompt_tokens": int(usage.get("prompt_tokens") or 0),
            "completion_tokens": int(usage.get("completion_tokens") or 0),
        }
        backend.last_latency_ms = _payload.get("latency_ms")
        backend.last_finish_reason = _payload.get("finish_reason")
        backend.last_raw = str(_payload.get("raw_response") or "")
        return backend.last_raw

    backend._complete = _cached
    try:
        return pipeline.run(prompt_unit)
    finally:
        backend._complete = original


def cwe_tier(predicted: str, gold: str, kb: CWEKnowledgeBase) -> str:
    """exact | parent_child | peer | none. Peers are not family."""
    if predicted == gold:
        return "exact"
    parent_child: set[str] = set()
    peers: set[str] = set()
    if gold in kb.entries:
        rel = kb.relationships(gold)
        parent_child.update(rel.parents)
        parent_child.update(rel.children)
        peers.update(rel.peers)
    if predicted in kb.entries:
        rel = kb.relationships(predicted)
        parent_child.update(rel.parents)
        parent_child.update(rel.children)
        peers.update(rel.peers)
    if predicted in parent_child or gold in parent_child:
        return "parent_child"
    if predicted in peers or gold in peers:
        return "peer"
    return "none"


def enrich_trial_cwe_fields(trial: dict[str, Any], kb: CWEKnowledgeBase | None = None) -> dict[str, Any]:
    """Recompute exact/parent-child/peer columns from unit_decisions (no LLM)."""
    rows = trial.get("unit_decisions") or []
    if not rows:
        return trial
    store = kb or CWEKnowledgeBase.load()
    exact = parent_child = peer = family = abstain = 0
    for row in rows:
        predicted = str(row.get("predicted_cwe") or "")
        gold = str(row.get("gold_cwe") or "")
        tier = cwe_tier(predicted, gold, store)
        row["cwe_tier"] = tier
        row["cwe_exact"] = tier == "exact"
        row["cwe_parent_child"] = tier in {"exact", "parent_child"}
        row["cwe_peer"] = tier == "peer"
        row["cwe_family"] = tier in {"exact", "parent_child"}
        if row.get("decision") == "uncertain":
            abstain += 1
        if tier == "exact":
            exact += 1
        if tier in {"exact", "parent_child"}:
            parent_child += 1
            family += 1
        elif tier == "peer":
            peer += 1
    total = len(rows)
    trial["cwe_exact_match"] = {"correct": exact, "total": total}
    trial["cwe_parent_child_match"] = {"correct": parent_child, "total": total}
    trial["cwe_peer_match"] = {"correct": peer, "total": total}
    trial["cwe_family_match"] = {"correct": family, "total": total}
    trial["cwe_family_definition"] = "exact or parent/child; peers are a separate column"
    trial["abstain_n"] = abstain
    trial["abstain_rate"] = (abstain / total) if total else 0.0
    return trial


def _cwe_match(
    rows: list[Any],
    units: list[SeedUnit],
    kb: CWEKnowledgeBase,
) -> tuple[dict[str, int], dict[str, int], dict[str, int], dict[str, int]]:
    """Exact, parent/child, peer-only, and family (exact|parent_child) counts."""
    exact = {"correct": 0, "total": 0}
    parent_child = {"correct": 0, "total": 0}
    peer = {"correct": 0, "total": 0}
    family = {"correct": 0, "total": 0}
    for row, unit in zip(rows, units, strict=True):
        if row is None:
            continue
        predicted = row.result.cwe.id
        gold = unit.cwe_id
        exact["total"] += 1
        parent_child["total"] += 1
        peer["total"] += 1
        family["total"] += 1
        tier = cwe_tier(predicted, gold, kb)
        if tier == "exact":
            exact["correct"] += 1
            parent_child["correct"] += 1
            family["correct"] += 1
        elif tier == "parent_child":
            parent_child["correct"] += 1
            family["correct"] += 1
        elif tier == "peer":
            peer["correct"] += 1
    return exact, parent_child, peer, family


def _token_usage(rows: list[Any]) -> dict[str, Any]:
    prompt = sum(row.prompt_tokens or 0 for row in rows)
    completion = sum(row.completion_tokens or 0 for row in rows)
    latencies = [row.latency_ms for row in rows if row.latency_ms is not None]
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt + completion,
        "latency_ms_mean": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "latency_ms_max": max(latencies) if latencies else None,
    }


def _unit_decision(unit: SeedUnit, row: Any, kb: CWEKnowledgeBase) -> dict[str, Any]:
    predicted = row.result.cwe.id
    gold = unit.cwe_id
    tier = cwe_tier(predicted, gold, kb)
    checks = {check.name: check.passed for check in row.report.checks}
    return {
        "unit_id": unit.unit_id,
        "prompt_id": row.unit_id,
        "decision": row.result.decision,
        "gold_label": unit.label,
        "predicted_cwe": predicted,
        "gold_cwe": gold,
        "cwe_exact": tier == "exact",
        "cwe_parent_child": tier in {"exact", "parent_child"},
        "cwe_peer": tier == "peer",
        "cwe_family": tier in {"exact", "parent_child"},
        "cwe_tier": tier,
        "cwe_clamped_from": getattr(row, "cwe_clamped_from", None),
        "path": row.path,
        "reasoner": row.reasoner,
        "model": row.model,
        "fallback_reason": row.fallback_reason,
        "n_attempts": row.n_attempts,
        "prompt_tokens": row.prompt_tokens,
        "completion_tokens": row.completion_tokens,
        "latency_ms": row.latency_ms,
        "prompt_chars": row.prompt_chars,
        "truncated": row.truncated,
        "slice_strategy": row.slice_strategy,
        "validator_passed": row.report.passed,
        "cited_lines": checks.get("cited_lines"),
        "cited_lines_normalized": checks.get("cited_lines_normalized"),
        "sast_disagreement": any(item.name == "sast_disagreement" for item in row.report.warnings),
    }


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


def trial_retrieval_units(
    retriever: HybridRetriever,
    units: list[SeedUnit],
    suite: str,
    split: str,
    disclaimer: str,
) -> dict[str, Any]:
    """Retrieval quality on detection units: sanitized evidence/sink window as the
    query, gold CWE as the relevant id. No LLM calls. Nearby Juliet ids are valid
    targets now that the KB is the official MITRE subset."""
    from cwe_vuln.dataset.sanitize import retrieval_query_text
    from cwe_vuln.models.retrieval import RetrievalQuery

    queries = []
    for unit in units:
        clean = sanitize_unit(unit)
        retriever.units_by_id[clean.unit_id] = clean
        queries.append(
            RetrievalQuery(
                query_id=unit.unit_id,
                query=retrieval_query_text(clean),
                relevant_cwes=(unit.cwe_id,),
                unit_id=clean.unit_id,
            )
        )
    report = evaluate_retriever(retriever, queries, k_values=(1, 3, 5))
    return {
        "trial_id": f"retrieval_units_{split}",
        "date": utc_now(),
        "suite": suite,
        "split": split,
        "evaluation_scope": "public_suite_sample_retrieval" if suite != "research" else "authored_corpus_not_a_public_benchmark",
        "disclaimer": disclaimer,
        "status": "ok",
        "config": {
            "embedder": retriever.embedder_name,
            "k_values": [1, 3, 5],
            "n_units": len(units),
            "query": "sanitized_evidence_or_sink_window",
        },
        "metrics": report["systems"],
        "notes": (
            "Per-unit retrieval on the same evidence/sink window the LLM sees; "
            "relevant id = gold CWE."
        ),
        "error": None,
        "embedder": retriever.embedder_name,
    }


def _counts(values) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        if not value:
            continue
        counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def _is_rate_limit(text: str) -> bool:
    lowered = text.lower()
    return (
        "429" in text
        or "rate limit" in lowered
        or "rate_limit" in lowered
        or "tokens per day" in lowered
        or "tokens per minute" in lowered
    )


def _make_pipeline(
    retriever: HybridRetriever,
    llm: LLMReasoner | None,
    skip_llm_when_sast_hits: bool,
    use_llm: bool,
) -> Pipeline:
    from cwe_vuln.agents import EvidenceAgent, KnowledgeAgent, ReasoningAgent, ValidatorAgent

    return Pipeline(
        extractor=EvidenceAgent(),
        retriever=KnowledgeAgent(retriever),
        reasoner=ReasoningAgent(TemplateReasoner()),
        validator=ValidatorAgent(),
        llm_reasoner=ReasoningAgent(llm) if (use_llm and llm is not None) else None,
        skip_llm_when_sast_hits=skip_llm_when_sast_hits,
        use_llm_if_available=use_llm,
    )


def _build_llm(model: str) -> LLMReasoner | None:
    provider = OpenAICompatProvider.from_env(model=model)
    if provider is None:
        return None
    return LLMReasoner(provider=provider)


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
    for name in (settings.llm_model(), *fallback_models()):
        if name and name not in ordered:
            ordered.append(name)
    return ordered


def run_research_suite(ablation: str = "none") -> list[dict[str, Any]]:
    if ablation != "template" and not settings.llm_ready():
        raise MissingLLMKeyError(missing_key_message())

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


def _juliet_label(trial: dict[str, Any], extra_notes: str, extra_config: dict[str, Any] | None = None) -> dict[str, Any]:
    trial["evaluation_scope"] = "juliet_java_v1_3_mapped_subset"
    trial["disclaimer"] = JULIET_DISCLAIMER
    trial["juliet_version"] = JULIET_VERSION
    trial["cwe_mapping"] = mapping_notes()
    trial["notes"] = f"{extra_notes} {trial.get('notes') or ''}".strip()
    if extra_config:
        config = dict(trial.get("config") or {})
        config.update(extra_config)
        trial["config"] = config
    return trial


def _load_juliet(tree: Path | None, require_download: bool) -> tuple[list[SeedUnit], dict[str, Any]]:
    provenance: dict[str, Any] = {}
    if tree is not None:
        units = load_juliet_units(tree=tree)
        provenance = {"method": "local_tree", "tree": str(tree)}
        return units, provenance
    try:
        prov = ensure_juliet() if require_download else None
        units = load_juliet_units(require_download=require_download)
        if prov is not None:
            provenance = prov.as_dict()
        else:
            path = provenance_path()
            if path.is_file():
                provenance = json.loads(path.read_text(encoding="utf-8"))
        return units, provenance
    except JulietError as exc:
        raise JulietError(str(exc)) from exc


def run_juliet_sast_suite(tree: Path | None = None) -> list[dict[str, Any]]:
    try:
        units, provenance = _load_juliet(tree, require_download=tree is None)
    except JulietError as exc:
        return [
            _failed_trial(
                "sast_regex_juliet",
                "juliet_mapped",
                "juliet-sast",
                "Juliet download or parse failed. OWASP Benchmark not run.",
                str(exc),
                {"suite": "juliet-sast", "backend": "regex"},
            )
        ]
    trial = trial_sast(units, "juliet_mapped", "juliet-sast")
    trial["trial_id"] = "sast_regex_juliet"
    counts = _cwe_label_counts(units)
    return [
        _juliet_label(
            trial,
            extra_notes=(
                f"Full regex SAST on ingested Juliet Java v{JULIET_VERSION} mapped folders. "
                f"n={len(units)}. CWE-502 has no Juliet Java folder. Retrieval@Juliet skipped."
            ),
            extra_config={"provenance": provenance, "per_cwe_n": counts},
        )
    ]


def run_juliet_llm_suite(
    ablation: str,
    tree: Path | None = None,
    per_cwe: int = DEFAULT_PER_CWE,
    sample_seed: int = SAMPLE_SEED,
    manifest_path: Path | None = None,
) -> list[dict[str, Any]]:
    try:
        units, provenance = _load_juliet(tree, require_download=tree is None)
    except JulietError as exc:
        return [
            _failed_trial(
                "llm_then_juliet_sample",
                "juliet_llm_sample",
                "juliet-llm-sample",
                "Juliet download or parse failed.",
                str(exc),
                {"suite": "juliet-llm-sample"},
            )
        ]
    sample = stratified_sample(
        units, per_cwe=per_cwe, seed=sample_seed, cwe_ids=LLM_SAMPLE_CWES
    )
    dest_manifest = manifest_path or sample_manifest_path()
    write_sample_manifest(sample, dest_manifest, per_cwe=per_cwe, seed=sample_seed, provenance=provenance)
    try:
        sample = load_sample_units(units, dest_manifest)
    except JulietError:
        pass
    retriever = HybridRetriever.load(allow_download=True)
    trials: list[dict[str, Any]] = [
        _juliet_label(
            trial_pipeline(
                "template_juliet_sample",
                sample,
                "juliet_llm_sample",
                "juliet-llm-sample",
                _make_pipeline(retriever, None, skip_llm_when_sast_hits=True, use_llm=False),
                notes="Ablation: TemplateReasoner on the Juliet LLM sample. Not the system of record.",
                evaluation_scope="juliet_java_v1_3_stratified_sample",
                disclaimer=JULIET_DISCLAIMER,
            ),
            extra_notes=f"Template ablation. Sample n={len(sample)} seed={sample_seed} per_cwe={per_cwe}.",
            extra_config={"provenance": provenance, "sample_manifest": str(dest_manifest)},
        )
    ]
    trials.append(
        _juliet_label(
            trial_retrieval_units(retriever, sample, "juliet-llm-sample", "juliet_llm_sample", JULIET_DISCLAIMER),
            extra_notes="Retrieval on the LLM sample units; relevant id = gold CWE.",
        )
    )
    if ablation == "template":
        return trials
    if not settings.llm_ready():
        raise MissingLLMKeyError(missing_key_message())
    llm, model_notes = _llm_with_fallback()
    if llm is None:
        trials.append(
            _failed_trial(
                "llm_then_juliet_sample",
                "juliet_llm_sample",
                "juliet-llm-sample",
                model_notes,
                model_notes,
                {"reasoner": "llm", "candidates": _candidate_models()},
            )
        )
        return trials
    then_pipe = _make_pipeline(retriever, llm, skip_llm_when_sast_hits=False, use_llm=True)
    trials.append(
        _juliet_label(
            trial_pipeline(
                "llm_then_juliet_sample",
                sample,
                "juliet_llm_sample",
                "juliet-llm-sample",
                then_pipe,
                notes="Live Groq on the stratified Juliet sample. " + model_notes,
                delay_seconds=1.5,
                stop_on_rate_limit=True,
                evaluation_scope="juliet_java_v1_3_stratified_sample",
                disclaimer=JULIET_DISCLAIMER,
            ),
            extra_notes=f"System of record on sample n={len(sample)} (not the full ingested set).",
            extra_config={"provenance": provenance, "sample_manifest": str(dest_manifest)},
        )
    )
    return trials


def _load_public_units(name: str, tree: Path | None, require_download: bool) -> tuple[list[SeedUnit], dict[str, Any]]:
    spec = SUITES[name]
    provenance: dict[str, Any] = {}
    kwargs: dict[str, Any] = {"tree": tree, "require_download": require_download}
    if name in {"vul4j", "cvefixes-java-slice"}:
        kwargs["fetch_patches"] = tree is None
    if tree is None:
        try:
            ensured = spec.ensure()
            if isinstance(ensured, dict):
                provenance = ensured
            elif hasattr(ensured, "as_dict"):
                provenance = ensured.as_dict()
        except Exception as exc:
            raise SuiteError(str(exc)) from exc
    units = spec.loader(**kwargs)
    path = spec.provenance()
    if not provenance and path.is_file():
        provenance = json.loads(path.read_text(encoding="utf-8"))
    return units, provenance


def run_public_sast_suite(name: str, tree: Path | None = None) -> list[dict[str, Any]]:
    spec = SUITES[name]
    try:
        units, provenance = _load_public_units(name, tree, require_download=tree is None)
    except (SuiteError, JulietError) as exc:
        return [
            _failed_trial(
                f"sast_regex_{name.replace('-', '_')}",
                f"{name}_mapped",
                name,
                f"{name} download or parse failed.",
                str(exc),
                {"suite": name, "backend": "regex"},
            )
        ]
    trial = trial_sast(units, f"{name}_mapped", name)
    trial["trial_id"] = f"sast_regex_{name.replace('-', '_')}"
    trial["evaluation_scope"] = spec.evaluation_scope
    trial["disclaimer"] = spec.disclaimer
    trial["cwe_mapping"] = spec.notes(units)
    trial["config"] = {
        **(trial.get("config") or {}),
        "provenance": provenance,
        "per_cwe_n": _cwe_label_counts(units),
    }
    trial["notes"] = (
        f"Full regex SAST on ingested {name} units n={len(units)}. "
        "Missing thesis CWEs are 'not present', not relabeled."
    )
    return [trial]


def run_public_llm_suite(
    name: str,
    ablation: str,
    tree: Path | None = None,
    sample_n: int = DEFAULT_SUITE_SAMPLE_N,
    sample_seed: int = SAMPLE_SEED,
    manifest_path: Path | None = None,
) -> list[dict[str, Any]]:
    spec = SUITES[name]
    try:
        units, provenance = _load_public_units(name, tree, require_download=tree is None)
    except (SuiteError, JulietError) as exc:
        return [
            _failed_trial(
                f"llm_then_{name.replace('-', '_')}_sample",
                f"{name}_llm_sample",
                f"{name}-llm-sample",
                f"{name} download or parse failed.",
                str(exc),
                {"suite": f"{name}-llm-sample"},
            )
        ]
    dest_manifest = manifest_path or spec.sample_manifest()
    if dest_manifest.is_file() and tree is None:
        try:
            sample = load_suite_sample_units(units, dest_manifest)
        except SuiteError:
            sample = stratified_suite_sample(units, n=sample_n, seed=sample_seed)
            write_suite_sample_manifest(
                name, sample, dest_manifest, n_target=sample_n, seed=sample_seed, provenance=provenance
            )
    else:
        sample = stratified_suite_sample(units, n=sample_n, seed=sample_seed)
        write_suite_sample_manifest(
            name, sample, dest_manifest, n_target=sample_n, seed=sample_seed, provenance=provenance
        )
    retriever = HybridRetriever.load(allow_download=True)
    trials: list[dict[str, Any]] = []
    template = trial_pipeline(
        f"template_{name.replace('-', '_')}_sample",
        sample,
        f"{name}_llm_sample",
        f"{name}-llm-sample",
        _make_pipeline(retriever, None, skip_llm_when_sast_hits=True, use_llm=False),
        notes=f"Ablation: TemplateReasoner on the {name} LLM sample. Not the system of record.",
        evaluation_scope=spec.evaluation_scope + "_stratified_sample",
        disclaimer=spec.disclaimer,
    )
    template["cwe_mapping"] = spec.notes(sample)
    template["config"] = {**(template.get("config") or {}), "provenance": provenance, "sample_manifest": str(dest_manifest)}
    trials.append(template)
    trials.append(
        trial_retrieval_units(retriever, sample, f"{name}-llm-sample", f"{name}_llm_sample", spec.disclaimer)
    )
    if ablation == "template":
        return trials
    if not settings.llm_ready():
        raise MissingLLMKeyError(missing_key_message())
    llm, model_notes = _llm_with_fallback()
    if llm is None:
        trials.append(
            _failed_trial(
                f"llm_then_{name.replace('-', '_')}_sample",
                f"{name}_llm_sample",
                f"{name}-llm-sample",
                model_notes,
                model_notes,
                {"reasoner": "llm", "candidates": _candidate_models()},
            )
        )
        return trials
    then_pipe = _make_pipeline(retriever, llm, skip_llm_when_sast_hits=False, use_llm=True)
    live = trial_pipeline(
        f"llm_then_{name.replace('-', '_')}_sample",
        sample,
        f"{name}_llm_sample",
        f"{name}-llm-sample",
        then_pipe,
        notes=f"Live Groq on the stratified {name} sample. " + model_notes,
        delay_seconds=2.0,
        stop_on_rate_limit=True,
        evaluation_scope=spec.evaluation_scope + "_stratified_sample",
        disclaimer=spec.disclaimer,
    )
    live["cwe_mapping"] = spec.notes(sample)
    live["config"] = {**(live.get("config") or {}), "provenance": provenance, "sample_manifest": str(dest_manifest)}
    trials.append(live)
    return trials


def write_six_summary(results_dir: Path) -> tuple[Path, Path]:
    trials: list[dict[str, Any]] = []
    known: set[str] = set()
    for path in sorted(results_dir.glob("*.json")):
        if path.name in {"summary.json", "juliet-eval-summary.json"} or path.name.endswith("-eval-summary.json"):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        trial_id = payload.get("trial_id")
        if not trial_id or trial_id in known:
            continue
        known.add(trial_id)
        trials.append(payload)
    detection = [
        item
        for item in trials
        if isinstance(item.get("metrics"), dict) and "precision" in (item.get("metrics") or {})
    ]
    summary = {
        "generated_at": utc_now(),
        "evaluation_scope": "six_public_java_suites",
        "disclaimer": SUITES["owasp-benchmark"].disclaimer,
        "novelty": (
            "Novelty claim is the method (SAST evidence + hybrid CWE retrieval + schema-bound Groq) "
            "versus these corpora and regex/template baselines — not 'first system ever' or 100% novelty."
        ),
        "trials": [
            {
                "trial_id": item["trial_id"],
                "suite": item.get("suite") or (item.get("config") or {}).get("suite"),
                "status": item.get("status"),
                "n_units": item.get("n_units"),
                "n_scored": item.get("n_scored"),
                "metrics": item.get("metrics"),
                "per_cwe": item.get("per_cwe"),
                "rate_limited": item.get("rate_limited"),
                "notes": item.get("notes"),
                "error": item.get("error"),
            }
            for item in trials
        ],
        "detection_table": [
            {
                "system": item["trial_id"],
                "suite": item.get("suite") or (item.get("config") or {}).get("suite"),
                "status": item.get("status"),
                "precision": item["metrics"]["precision"],
                "recall": item["metrics"]["recall"],
                "f1": item["metrics"]["f1"],
                "fp": item["metrics"]["fp"],
                "fn": item["metrics"]["fn"],
                "n": item["metrics"]["support"],
                "validation_pass": item.get("validation_pass"),
                "rate_limited": item.get("rate_limited"),
            }
            for item in detection
        ],
    }
    json_path = results_dir / "summary.json"
    json_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Six-suite evaluation summary",
        "",
        summary["disclaimer"],
        "",
        f"- Generated: `{summary['generated_at']}`",
        "",
        "| System | Suite | Status | Precision | Recall | F1 | FP | FN | n |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary["detection_table"]:
        lines.append(
            f"| {row['system']} | {row.get('suite')} | {row.get('status')} | "
            f"{row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} | "
            f"{row['fp']} | {row['fn']} | {row['n']} |"
        )
    lines.extend(["", "## Trial log", ""])
    for item in summary["trials"]:
        err = f" error={item['error']}" if item.get("error") else ""
        lines.append(f"- `{item['trial_id']}` suite={item.get('suite')} status={item['status']} n={item.get('n_units')}{err}")
    lines.append("")
    md_path = results_dir / "summary.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def _cwe_label_counts(units: list[SeedUnit]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for unit in units:
        bucket = out.setdefault(unit.cwe_id, {"vulnerable": 0, "not_vulnerable": 0, "n": 0})
        bucket[unit.label] += 1
        bucket["n"] += 1
    return out


def write_benchmark_summary(trials: list[dict[str, Any]], dest: Path) -> tuple[Path, Path]:
    dest.mkdir(parents=True, exist_ok=True)
    detection = [
        item
        for item in trials
        if isinstance(item.get("metrics"), dict) and "precision" in (item.get("metrics") or {})
    ]
    summary = {
        "generated_at": utc_now(),
        "evaluation_scope": "juliet_java_v1_3_mapped_subset",
        "disclaimer": JULIET_DISCLAIMER,
        "juliet_version": JULIET_VERSION,
        "cwe_mapping": mapping_notes(),
        "trials": [
            {
                "trial_id": item["trial_id"],
                "status": item.get("status"),
                "n_units": item.get("n_units"),
                "n_scored": item.get("n_scored"),
                "metrics": item.get("metrics"),
                "per_cwe": item.get("per_cwe"),
                "rate_limited": item.get("rate_limited"),
                "notes": item.get("notes"),
                "error": item.get("error"),
            }
            for item in trials
        ],
        "detection_table": [
            {
                "system": item["trial_id"],
                "status": item.get("status"),
                "precision": item["metrics"]["precision"],
                "recall": item["metrics"]["recall"],
                "f1": item["metrics"]["f1"],
                "fp": item["metrics"]["fp"],
                "fn": item["metrics"]["fn"],
                "n": item["metrics"]["support"],
                "validation_pass": item.get("validation_pass"),
            }
            for item in detection
        ],
    }
    json_path = dest / "juliet-eval-summary.json"
    json_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    md_path = dest / "juliet-eval-summary.md"
    md_path.write_text(_benchmark_markdown(summary), encoding="utf-8")
    return json_path, md_path


def _benchmark_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Juliet Java evaluation summary",
        "",
        JULIET_DISCLAIMER,
        "",
        f"- Generated: `{summary['generated_at']}`",
        f"- Juliet version: `{summary.get('juliet_version')}`",
        "",
        "| System | Status | Precision | Recall | F1 | FP | FN | n |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary["detection_table"]:
        lines.append(
            f"| {row['system']} | {row.get('status')} | {row['precision']:.3f} | {row['recall']:.3f} | "
            f"{row['f1']:.3f} | {row['fp']} | {row['fn']} | {row['n']} |"
        )
    lines.extend(["", "## Trial log", ""])
    for item in summary["trials"]:
        err = f" error={item['error']}" if item.get("error") else ""
        lines.append(f"- `{item['trial_id']}` status={item['status']} n={item.get('n_units')}{err}")
    lines.append("")
    return "\n".join(lines)


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
    public_names = sorted(set(list(SAST_SUITE_NAMES) + list(LLM_SUITE_NAMES) + ["juliet-sast", "all-sast", "thesis"]))
    parser = argparse.ArgumentParser(
        description="Run authored-corpus, public-suite, or thesis-defendable evaluation trials."
    )
    parser.add_argument(
        "--suite",
        choices=["research", "seed", "all", *public_names],
        default="research",
    )
    parser.add_argument(
        "--ablation",
        choices=["none", "template", "skip-llm"],
        default="none",
        help="none = live LLM (default). template = SAST/template contrast only. skip-llm = cost-path ablation.",
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
    parser.add_argument("--juliet-tree", type=Path, default=None, help="Local Juliet testcases tree (tests/fixtures).")
    parser.add_argument("--suite-tree", type=Path, default=None, help="Local suite tree for mapper tests.")
    parser.add_argument("--per-cwe", type=int, default=DEFAULT_PER_CWE)
    parser.add_argument("--sample-n", type=int, default=DEFAULT_SUITE_SAMPLE_N)
    parser.add_argument("--sample-seed", type=int, default=SAMPLE_SEED)
    parser.add_argument(
        "--include-model-ablation",
        action="store_true",
        help="C7: re-run the authored traps on fallback models. Skip unless TPD remains.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip thesis trials that already have status=ok on disk.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="Stop scheduling live LLM thesis trials once recorded usage reaches this budget.",
    )
    args = parser.parse_args(argv)
    ablation = args.ablation
    if args.offline or args.skip_llm:
        ablation = "template"

    public = args.suite not in {"research", "seed", "all", "thesis"}
    out = args.output_dir or (benchmarks_results_dir() if public else experiments_dir())
    if args.suite == "thesis":
        from cwe_vuln.framework.thesis import thesis_results_dir

        out = args.output_dir or thesis_results_dir()
    out.mkdir(parents=True, exist_ok=True)
    global RAW_LLM_DIR
    RAW_LLM_DIR = out / "raw_llm"
    tree = args.suite_tree or args.juliet_tree
    trials: list[dict[str, Any]] = []
    try:
        if args.suite == "thesis":
            from cwe_vuln.framework.thesis import run_thesis_eval, thesis_results_dir

            dest = args.output_dir or thesis_results_dir()
            trials.extend(
                run_thesis_eval(
                    ablation=ablation,
                    juliet_tree=tree,
                    output_dir=dest,
                    include_model_ablation=args.include_model_ablation,
                    resume=args.resume,
                    max_tokens=args.max_tokens,
                )
            )
        elif args.suite == "all-sast":
            for name in SAST_SUITE_NAMES:
                if name == "juliet":
                    trials.extend(run_juliet_sast_suite(tree=tree if tree else None))
                else:
                    trials.extend(run_public_sast_suite(name, tree=None))
        elif args.suite in {"juliet-sast", "juliet"}:
            trials.extend(run_juliet_sast_suite(tree=tree))
        elif args.suite == "juliet-llm-sample":
            trials.extend(
                run_juliet_llm_suite(
                    ablation=ablation,
                    tree=tree,
                    per_cwe=args.per_cwe,
                    sample_seed=args.sample_seed,
                    manifest_path=(
                        sample_manifest_path()
                        if tree is None
                        else (out / "juliet_llm_sample.json")
                    ),
                )
            )
        elif public:
            name, llm = resolve_suite(args.suite)
            if llm:
                if name == "juliet":
                    trials.extend(
                        run_juliet_llm_suite(
                            ablation=ablation,
                            tree=tree,
                            per_cwe=args.per_cwe,
                            sample_seed=args.sample_seed,
                        )
                    )
                else:
                    trials.extend(
                        run_public_llm_suite(
                            name,
                            ablation=ablation,
                            tree=tree,
                            sample_n=args.sample_n,
                            sample_seed=args.sample_seed,
                            manifest_path=(out / f"{name}_llm_sample.json") if tree is not None else None,
                        )
                    )
            else:
                if name == "juliet":
                    trials.extend(run_juliet_sast_suite(tree=tree))
                else:
                    trials.extend(run_public_sast_suite(name, tree=tree))
        else:
            if args.suite in {"research", "all"}:
                trials.extend(run_research_suite(ablation=ablation))
            if args.suite in {"seed", "all"}:
                trials.extend(run_seed_suite())
    except MissingLLMKeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (JulietError, SuiteError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    for trial in trials:
        path = write_trial(trial, out)
        print(f"wrote {path} status={trial.get('status')}")
    if args.suite == "thesis":
        print(f"thesis trials written under {out}")
        failed = [item for item in trials if item.get("status") == "failed"]
        return 1 if failed else 0
    if public:
        known = {item["trial_id"] for item in trials}
        extras: list[dict[str, Any]] = []
        for path in sorted(out.glob("*.json")):
            if path.name in {"summary.json", "juliet-eval-summary.json"} or "llm_sample" in path.name:
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            trial_id = payload.get("trial_id")
            if trial_id and trial_id not in known:
                extras.append(payload)
                known.add(trial_id)
        if args.suite.startswith("juliet"):
            json_path, md_path = write_benchmark_summary(trials + extras, out)
            print(JULIET_DISCLAIMER)
        else:
            json_path, md_path = write_six_summary(out)
        print(f"wrote {json_path}")
        print(f"wrote {md_path}")
        failed = [item for item in trials if item.get("status") == "failed"]
        return 1 if failed else 0

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
