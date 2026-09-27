"""Argument parsing for cwe-vuln-eval. Flags match the historical eval.main CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cwe_vuln.config import MissingLLMKeyError
from cwe_vuln.dataset.common import DEFAULT_SUITE_SAMPLE_N, SuiteError
from cwe_vuln.dataset.juliet import (
    DEFAULT_PER_CWE,
    SAMPLE_SEED,
    JulietError,
    sample_manifest_path,
)
from cwe_vuln.dataset.registry import LLM_SUITE_NAMES, SAST_SUITE_NAMES, resolve_suite
from cwe_vuln.framework.context import RunContext
from cwe_vuln.framework.summaries import write_benchmark_summary, write_six_summary, write_summary
from cwe_vuln.framework.trials import (
    DISCLAIMER,
    JULIET_DISCLAIMER,
    benchmarks_results_dir,
    experiments_dir,
    run_juliet_llm_suite,
    run_juliet_sast_suite,
    run_public_llm_suite,
    run_public_sast_suite,
    run_research_suite,
    run_seed_suite,
    write_trial,
)

def main(argv: list[str] | None = None, *, context: RunContext | None = None) -> int:
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
    if context is None:
        context = RunContext(raw_llm_dir=out / "raw_llm", replay=False)
    elif context.raw_llm_dir is None:
        context = RunContext(
            raw_llm_dir=out / "raw_llm",
            replay=context.replay,
            should_stop=context.should_stop,
            log=context.log,
        )
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
                    context=context,
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
                    context=context,
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
                            context=context,
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
                            context=context,
                        )
                    )
            else:
                if name == "juliet":
                    trials.extend(run_juliet_sast_suite(tree=tree))
                else:
                    trials.extend(run_public_sast_suite(name, tree=tree))
        else:
            if args.suite in {"research", "all"}:
                trials.extend(run_research_suite(ablation=ablation, context=context))
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
