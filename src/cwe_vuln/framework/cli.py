"""Thin CLI: run the orchestrated pipeline on seed units and write metrics."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cwe_vuln.config import MissingLLMKeyError, repo_root, settings
from cwe_vuln.dataset import load_seed
from cwe_vuln.models.metrics import binary_metrics
from cwe_vuln.orchestrator import Pipeline

SEED_ONLY = (
    "seed-only — not a benchmark. Metrics are the authored Java seed "
    "(test split default; pass --split all for all 12 units)."
)


def run_split(split: str, *, offline: bool = False) -> dict:
    units = load_seed(split=split) if split in {"train", "test"} else load_seed()
    pipeline = Pipeline.offline() if offline else Pipeline.default()
    rows = [pipeline.run(unit) for unit in units]
    y_true = [unit.is_vulnerable for unit in units]
    y_pred = [row.result.decision == "vulnerable" for row in rows]
    scores = binary_metrics(y_true, y_pred)
    embedder = getattr(pipeline.retriever, "embedder_name", "unknown")
    return {
        "assignment": "framework",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evaluation_scope": "authored_seed_only",
        "seed_only_not_a_benchmark": True,
        "disclaimer": SEED_ONLY,
        "split": split,
        "n_units": len(units),
        "embedder": embedder,
        "offline": offline,
        "llm_configured": bool(settings.llm_api_key()),
        "detector_path_counts": _path_counts(rows),
        "reasoner_counts": _reasoner_counts(rows),
        "validation_pass": sum(1 for row in rows if row.report.passed),
        "sast_disagreement": sum(1 for row in rows if row.report.warnings),
        "metrics": scores.as_dict(),
        "units": [row.to_dict() for row in rows],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the live Groq pipeline (SAST evidence → retrieve → LLM → validate)."
    )
    parser.add_argument("--split", choices=["test", "train", "all"], default="test")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Ablation: TemplateReasoner only. Not the system of record.",
    )
    args = parser.parse_args(argv)
    try:
        report = run_split(args.split, offline=args.offline)
    except MissingLLMKeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    names = {"test": "framework-seed.json", "all": "framework-seed-all.json", "train": "framework-seed-train.json"}
    output = args.output or (repo_root() / "results" / names[args.split])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md = output.with_suffix(".md")
    md.write_text(_markdown(report), encoding="utf-8")
    metrics = report["metrics"]
    print("Framework seed run — seed-only, not a benchmark")
    print(f"split={report['split']} n={report['n_units']} paths={report['detector_path_counts']}")
    print(
        f"precision={metrics['precision']:.3f} recall={metrics['recall']:.3f} "
        f"f1={metrics['f1']:.3f} fp={metrics['fp']} fn={metrics['fn']}"
    )
    print(f"wrote {output}")
    print(f"wrote {md}")
    return 0


def _path_counts(rows) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.path] = counts.get(row.path, 0) + 1
    return counts


def _reasoner_counts(rows) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        name = getattr(row, "reasoner", "template")
        counts[name] = counts.get(name, 0) + 1
    return counts


def _markdown(report: dict) -> str:
    m = report["metrics"]
    return "\n".join(
        [
            "# Framework seed results",
            "",
            "**seed-only — not a benchmark.**",
            "",
            report["disclaimer"],
            "",
            f"- Split: `{report['split']}` ({report['n_units']} units)",
            f"- Embedder: `{report.get('embedder')}`",
            f"- Offline ablation: `{report.get('offline')}`",
            f"- LLM configured: `{report.get('llm_configured')}`",
            f"- Validation pass: {report['validation_pass']}/{report['n_units']}",
            f"- SAST disagreement warnings: {report.get('sast_disagreement', 0)}",
            f"- Paths: `{report['detector_path_counts']}`",
            f"- Reasoners: `{report.get('reasoner_counts')}`",
            "",
            f"| Precision | Recall | F1 | TP | FP | TN | FN |",
            f"| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            f"| {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} |",
            "",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
