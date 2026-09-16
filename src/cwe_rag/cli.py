"""Command-line entry: detect a snippet or print seed-only metrics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cwe_rag.evaluate import evaluate_seed
from cwe_rag.pipeline import detect


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cwe-rag",
        description=(
            "Seed multi-agent CWE detector. Metrics from `eval` are seed-only."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    detect_p = sub.add_parser("detect", help="Analyze one snippet")
    src = detect_p.add_mutually_exclusive_group(required=True)
    src.add_argument("--code", help="Snippet passed on the command line")
    src.add_argument("--file", type=Path, help="Read snippet from a file")

    sub.add_parser("eval", help="Score the bundled seed cases (not a benchmark)")

    args = parser.parse_args(argv)
    if args.cmd == "detect":
        code = args.code if args.code is not None else args.file.read_text()
        print(json.dumps(detect(code).to_dict(), indent=2))
        return 0
    metrics = evaluate_seed()
    payload = {
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1": metrics.f1,
        "n_cases": metrics.n_cases,
        "cwe_id_accuracy": metrics.cwe_id_accuracy,
        "note": metrics.note,
    }
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
