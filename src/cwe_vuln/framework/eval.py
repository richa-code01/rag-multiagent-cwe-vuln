"""Compatibility facade for ``cwe-vuln-eval``.

Trial execution lives in ``trials``, summary writers in ``summaries``, and
argument parsing in ``cli_eval``. Names stay importable from this module so
existing callers and the console script do not move.
"""

from cwe_vuln.framework.cli_eval import main
from cwe_vuln.framework.context import RunContext
from cwe_vuln.framework.summaries import write_benchmark_summary, write_six_summary, write_summary
from cwe_vuln.framework.trials import (
    DISCLAIMER,
    JULIET_DISCLAIMER,
    benchmarks_results_dir,
    cwe_tier,
    enrich_trial_cwe_fields,
    experiments_dir,
    load_ok_trial,
    redact,
    run_juliet_llm_suite,
    run_juliet_sast_suite,
    run_public_llm_suite,
    run_public_sast_suite,
    run_research_suite,
    run_seed_suite,
    skipped_trial,
    trial_pipeline,
    trial_retrieval,
    trial_retrieval_units,
    trial_sast,
    trial_token_count,
    utc_now,
    write_trial,
)
from cwe_vuln.framework.trials import _llm_with_fallback, _make_pipeline

__all__ = [
    "DISCLAIMER",
    "JULIET_DISCLAIMER",
    "RunContext",
    "benchmarks_results_dir",
    "cwe_tier",
    "enrich_trial_cwe_fields",
    "experiments_dir",
    "load_ok_trial",
    "main",
    "redact",
    "run_juliet_llm_suite",
    "run_juliet_sast_suite",
    "run_public_llm_suite",
    "run_public_sast_suite",
    "run_research_suite",
    "run_seed_suite",
    "skipped_trial",
    "trial_pipeline",
    "trial_retrieval",
    "trial_retrieval_units",
    "trial_sast",
    "trial_token_count",
    "_llm_with_fallback",
    "_make_pipeline",
    "utc_now",
    "write_benchmark_summary",
    "write_six_summary",
    "write_summary",
    "write_trial",
]
