"""Write evaluation summary JSON and Markdown from trial payloads."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cwe_vuln.config import repo_root
from cwe_vuln.dataset.juliet import JULIET_VERSION, mapping_notes
from cwe_vuln.dataset.registry import SUITES
from cwe_vuln.framework.trials import DISCLAIMER, JULIET_DISCLAIMER, utc_now

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
        "- Seed n=12 (8/4 assignment split) · research test n=24 · corpus n=36",
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

