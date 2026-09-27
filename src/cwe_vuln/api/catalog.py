"""Read-only catalogs for the operator console: suites, providers, saved trials."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cwe_vuln.config import repo_root
from cwe_vuln.dataset.registry import LLM_SUITE_NAMES, SAST_SUITE_NAMES
from cwe_vuln.llm.spec import api_key_from_env, known_providers, resolve_spec

EVAL_SUITES = (
    "research",
    "seed",
    "all",
    "thesis",
    "all-sast",
    *SAST_SUITE_NAMES,
    *LLM_SUITE_NAMES,
    "juliet-sast",
)


def suite_catalog() -> dict[str, Any]:
    return {
        "eval_suites": list(EVAL_SUITES),
        "ablations": ["none", "template", "skip-llm"],
        "pipeline_splits": ["test", "train", "all"],
        "experiments": [
            {
                "id": "c2-resume",
                "title": "Finish C2 Juliet pairs",
                "command": "uv run cwe-vuln-eval --suite thesis --resume --max-tokens 200000",
                "note": "Scores the missing unit, then recomputes pair accuracy and the bootstrap CI. Does not fill a skipped row.",
            },
            {
                "id": "c4-juliet",
                "title": "C4 no-retrieval on Juliet pairs",
                "command": "uv run cwe-vuln-eval --suite thesis --resume --max-tokens 200000",
                "note": "llm_no_retrieval_juliet_pairs stays skipped until this run writes it. Do not claim RAG helps on Juliet before that file exists.",
            },
            {
                "id": "c3",
                "title": "C3 sliced Vul4J",
                "command": "uv run cwe-vuln-eval --suite thesis --resume --max-tokens 200000",
                "note": "Leave skipped if the daily token budget is already spent.",
            },
            {
                "id": "c7",
                "title": "C7 model ablation",
                "command": "uv run cwe-vuln-eval --suite thesis --resume --include-model-ablation --max-tokens 200000",
                "note": "Only with --include-model-ablation, and only if tokens remain.",
            },
            {
                "id": "c8",
                "title": "C8 human spot-check",
                "command": "labels in the Spot-check panel",
                "note": "Empty labels stay not_run. No inter-rater statistic.",
            },
        ],
    }


def provider_catalog() -> dict[str, Any]:
    rows = []
    for name in known_providers():
        spec = resolve_spec(name)
        models = [spec.default_model, *spec.fallback_models]
        deduped = [item for item in models if item]
        seen: list[str] = []
        for item in deduped:
            if item not in seen:
                seen.append(item)
        rows.append(
            {
                "name": spec.name,
                "default_model": spec.default_model,
                "models": seen,
                "base_url": spec.base_url,
                "requires_key": spec.requires_key,
                "key_configured": bool(api_key_from_env(spec)) or not spec.requires_key,
                "notes": spec.notes,
            }
        )
    return {"providers": rows}


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def thesis_summary(root: Path | None = None) -> dict[str, Any]:
    base = root or repo_root()
    summary = _read_json(base / "results" / "thesis" / "summary.json")
    retracted = _read_json(base / "results" / "benchmarks" / "summary.json")
    return {
        "thesis": summary,
        "public_sast": retracted,
        "retracted_note": (
            "Public-suite LLM rows from 2026-09-17 are retracted "
            "(gold-label leakage and silent Groq fallback). Regex SAST rows are kept."
        ),
    }


def load_trial(trial_id: str, root: Path | None = None) -> dict[str, Any] | None:
    base = root or repo_root()
    for directory in (
        base / "results" / "thesis",
        base / "results" / "experiments",
        base / "results" / "benchmarks",
    ):
        path = directory / f"{trial_id}.json"
        payload = _read_json(path)
        if payload is not None:
            payload = dict(payload)
            payload.pop("unit_decisions", None)
            decisions_path = path
            full = _read_json(decisions_path) or {}
            payload["unit_decisions"] = full.get("unit_decisions") or []
            return payload
    return None


def spotcheck_path(root: Path | None = None) -> Path:
    return (root or repo_root()) / "results" / "thesis" / "human_spotcheck.json"


def load_spotcheck(root: Path | None = None) -> dict[str, Any]:
    payload = _read_json(spotcheck_path(root))
    return payload or {"status": "not_run", "rows": [], "notes": "C8 file missing."}


def save_spotcheck(rows: list[dict[str, Any]], root: Path | None = None) -> dict[str, Any]:
    current = load_spotcheck(root)
    by_id = {str(row.get("unit_id")): row for row in rows}
    merged = []
    for row in current.get("rows") or []:
        update = by_id.get(str(row.get("unit_id")))
        if update:
            row = dict(row)
            row["explanation_correct"] = update.get("explanation_correct")
            row["remediation_useful"] = update.get("remediation_useful")
        merged.append(row)
    filled = [
        row
        for row in merged
        if row.get("explanation_correct") is not None and row.get("remediation_useful") is not None
    ]
    status = "not_run"
    notes = "C8 not run — labels are incomplete. No inter-rater statistic."
    if merged and len(filled) == len(merged):
        status = "submitted"
        notes = (
            "C8 labels submitted by a single rater. Not an inter-rater study and not a detection metric."
        )
    payload = dict(current)
    payload["rows"] = merged
    payload["status"] = status
    payload["n_labeled"] = len(filled)
    payload["notes"] = notes
    path = spotcheck_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload
