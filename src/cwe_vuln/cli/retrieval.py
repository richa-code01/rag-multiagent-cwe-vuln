"""Print hybrid Top-K CWE hits and/or persist Assignment 3 retrieval metrics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwe_vuln.config import repo_root
from cwe_vuln.retrieval import HybridRetriever, RetrievalQuery, evaluate_retriever, load_retrieval_queries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assignment 3 hybrid CWE retrieval (seed-only).")
    parser.add_argument("--query", help="Free-text query to rank CWE entries")
    parser.add_argument("--unit-id", dest="unit_id", default=None, help="Optional seed unit_id for SAST signal")
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--eval", action="store_true", help="Evaluate labeled seed queries and write results/")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    retriever = HybridRetriever.load()
    if args.query:
        query = RetrievalQuery(
            query_id="cli",
            query=args.query,
            relevant_cwes=(),
            unit_id=args.unit_id,
        )
        print(f"hybrid RRF Top-{args.k} for: {args.query!r}")
        for index, hit in enumerate(retriever.hybrid_rank(query)[: args.k], start=1):
            print(f"  {index}. {hit.cwe_id}  {hit.score:.4f}  {hit.name}")
        print("lexical TF-IDF:")
        for index, hit in enumerate(retriever.lexical_rank(args.query)[: args.k], start=1):
            print(f"  {index}. {hit.cwe_id}  {hit.score:.4f}  {hit.name}")
        sast = retriever.sast_rank(query)
        print("sast:", [hit.cwe_id for hit in sast] or "(no rule match)")
        if not args.eval:
            return 0

    queries = load_retrieval_queries()
    report = evaluate_retriever(retriever, queries)
    output = args.output or (repo_root() / "results" / "assignment-3-retrieval.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md = output.with_suffix(".md")
    md.write_text(_markdown(report), encoding="utf-8")
    print("Assignment 3 retrieval (authored seed only — not a benchmark)")
    systems = report["systems"]
    for name, scores in systems.items():
        print(
            f"  {name}: recall@1={scores['recall@1']:.3f} "
            f"recall@3={scores['recall@3']:.3f} mrr={scores['mrr']:.3f}"
        )
    print(f"wrote {output}")
    print(f"wrote {md}")
    sample = queries[0]
    print(f"sample hybrid Top-5 ({sample.query_id}): {sample.query}")
    for index, hit in enumerate(retriever.hybrid_rank(sample)[:5], start=1):
        print(f"  {index}. {hit.cwe_id}  {hit.name}")
    return 0


def _markdown(report: dict) -> str:
    lines = [
        "# Assignment 3 hybrid retrieval results",
        "",
        "**seed-only — not a benchmark.**",
        "",
        report["disclaimer"],
        "",
        f"- Queries: {report['n_queries']}",
        "",
        "## Macro metrics",
        "",
        "| System | Recall@1 | Recall@3 | Recall@5 | MRR |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name, scores in report["systems"].items():
        lines.append(
            f"| {name} | {scores['recall@1']:.3f} | {scores['recall@3']:.3f} | "
            f"{scores['recall@5']:.3f} | {scores['mrr']:.3f} |"
        )
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
