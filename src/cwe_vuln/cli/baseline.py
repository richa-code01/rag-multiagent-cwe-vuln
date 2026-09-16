"""Run the Assignment 1 regex baseline on the authored Java seed and persist metrics."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cwe_vuln.config import repo_root
from cwe_vuln.dataset import SeedUnit, load_seed
from cwe_vuln.models.metrics import BinaryMetrics, binary_metrics
from cwe_vuln.sast import Detection, detect, llm_detector_status

SEED_ONLY_DISCLAIMER = (
    "seed-only — not a benchmark. Metrics are computed only on this 12-unit "
    "authored pedagogical seed. Rules were written against the same seed. "
    "Do not treat these scores as Juliet, OWASP Benchmark, or Big-Vul results."
)


def evaluate_units(units: list[SeedUnit]) -> tuple[list[dict[str, Any]], BinaryMetrics]:
    rows: list[dict[str, Any]] = []
    y_true: list[bool] = []
    y_pred: list[bool] = []
    for unit in units:
        prediction = detect(unit)
        y_true.append(unit.is_vulnerable)
        y_pred.append(prediction.is_vulnerable)
        rows.append(_row(unit, prediction))
    return rows, binary_metrics(y_true, y_pred)


def build_report(units: list[SeedUnit]) -> dict[str, Any]:
    rows, overall = evaluate_units(units)
    train_units = [unit for unit in units if unit.split == "train"]
    test_units = [unit for unit in units if unit.split == "test"]
    _, train_metrics = evaluate_units(train_units)
    _, test_metrics = evaluate_units(test_units)

    per_cwe: dict[str, Any] = {}
    grouped: dict[str, list[SeedUnit]] = defaultdict(list)
    for unit in units:
        grouped[unit.cwe_id].append(unit)
    for cwe_id, group in grouped.items():
        _, scores = evaluate_units(group)
        per_cwe[cwe_id] = scores.as_dict()

    return {
        "assignment": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evaluation_scope": "authored_seed_only",
        "seed_only_not_a_benchmark": True,
        "disclaimer": SEED_ONLY_DISCLAIMER,
        "n_units": len(units),
        "split": {"train": len(train_units), "test": len(test_units)},
        "detector": {
            "type": "regex_sast_style",
            "llm_detector": llm_detector_status(),
        },
        "overall": overall.as_dict(),
        "train": train_metrics.as_dict(),
        "test": test_metrics.as_dict(),
        "per_cwe": per_cwe,
        "predictions": rows,
    }


def persist_report(report: dict[str, Any], output_json: Path) -> tuple[Path, Path]:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    output_md = output_json.with_suffix(".md")
    output_md.write_text(_markdown(report), encoding="utf-8")
    return output_json, output_md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the Assignment 1 regex baseline on the Java CWE seed."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="JSON output path (default: results/assignment-1-baseline.json)",
    )
    args = parser.parse_args(argv)

    root = repo_root()
    units = load_seed(root)
    report = build_report(units)
    output = args.output or (root / "results" / "assignment-1-baseline.json")
    json_path, md_path = persist_report(report, output)

    overall = report["overall"]
    print("Assignment 1 baseline (authored seed only — not a benchmark)")
    print(f"units: {report['n_units']}  train: {report['split']['train']}  test: {report['split']['test']}")
    print(
        "overall: "
        f"precision={overall['precision']:.3f} recall={overall['recall']:.3f} "
        f"f1={overall['f1']:.3f} fp={overall['fp']} fn={overall['fn']}"
    )
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    return 0


def _row(unit: SeedUnit, prediction: Detection) -> dict[str, Any]:
    return {
        "unit_id": unit.unit_id,
        "cwe_id": unit.cwe_id,
        "split": unit.split,
        "label": unit.label,
        "predicted_label": prediction.predicted_label,
        "predicted_cwes": list(prediction.predicted_cwes),
        "matched_rules": list(prediction.matched_rules),
        "correct": unit.label == prediction.predicted_label,
    }


def _markdown(report: dict[str, Any]) -> str:
    overall = report["overall"]
    train = report["train"]
    test = report["test"]
    lines = [
        "# Assignment 1 baseline results",
        "",
        "**seed-only — not a benchmark.**",
        "",
        report["disclaimer"],
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Detector: `{report['detector']['type']}`",
        f"- LLM detector: `{report['detector']['llm_detector']}`",
        f"- Units: {report['n_units']} (train {report['split']['train']} / test {report['split']['test']})",
        "",
        "## Binary metrics (vulnerable vs not_vulnerable)",
        "",
        "| Split | Precision | Recall | F1 | TP | FP | TN | FN |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        _metric_row("overall", overall),
        _metric_row("train", train),
        _metric_row("test", test),
        "",
        "## Per-CWE (seed subsets only)",
        "",
        "| CWE | Precision | Recall | F1 | TP | FP | TN | FN |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for cwe_id, scores in report["per_cwe"].items():
        lines.append(_metric_row(cwe_id, scores))
    lines.extend(["", "## Predictions", ""])
    for row in report["predictions"]:
        mark = "ok" if row["correct"] else "error"
        lines.append(
            f"- `{row['unit_id']}` [{row['split']}] gold={row['label']} "
            f"pred={row['predicted_label']} rules={row['matched_rules'] or '—'} ({mark})"
        )
    lines.append("")
    return "\n".join(lines)


def _metric_row(name: str, scores: dict[str, Any]) -> str:
    return (
        f"| {name} | {scores['precision']:.3f} | {scores['recall']:.3f} | "
        f"{scores['f1']:.3f} | {scores['tp']} | {scores['fp']} | {scores['tn']} | {scores['fn']} |"
    )


if __name__ == "__main__":
    raise SystemExit(main())
