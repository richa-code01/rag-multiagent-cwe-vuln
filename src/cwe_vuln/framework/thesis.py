"""Thesis-defendable evaluation (Phase C). Live LLM, TPD-aware, never invents fill-ins.

C1 authored traps, C2 Juliet pairs + bootstrap CI, C3 sliced real-world,
C4 component ablations, C5 Semgrep-or-skip, C7 model ablation-or-skip,
C8 human-spotcheck template (not filled in).
"""

from __future__ import annotations

import json
import random
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cwe_vuln.config import repo_root, settings
from cwe_vuln.dataset import SeedUnit, load_juliet_units, load_research_corpus
from cwe_vuln.dataset.juliet import (
    JULIET_VERSION,
    LLM_SAMPLE_CWES,
    MULTI_FILE_STEM,
    SAMPLE_SEED,
    is_multi_file_juliet_unit,
    mapping_notes,
)
from cwe_vuln.dataset.registry import SUITES
from cwe_vuln.dataset.sanitize import slice_unit
from cwe_vuln.framework.eval import (
    DISCLAIMER,
    JULIET_DISCLAIMER,
    _llm_with_fallback,
    _make_pipeline,
    load_ok_trial,
    skipped_trial,
    trial_pipeline,
    trial_retrieval_units,
    trial_sast,
    trial_token_count,
    utc_now,
    write_trial,
)
from cwe_vuln.framework.pairs import (
    Pair,
    bootstrap_ci,
    build_pairs,
    flatten_pairs,
    pair_accuracy,
    sample_pairs,
)
from cwe_vuln.llm import fallback_models
from cwe_vuln.models.metrics import binary_metrics
from cwe_vuln.orchestrator import Pipeline
from cwe_vuln.orchestrator.ablations import EmptyExtractor, EmptyRetriever
from cwe_vuln.reasoner import LLMReasoner, TemplateReasoner
from cwe_vuln.retrieval import HybridRetriever

THESIS_FAMILIES: tuple[str, ...] = LLM_SAMPLE_CWES
PAIR_PER_CWE = 3  # 6 families × 3 pairs = 18 pairs = 36 units (TPD-tight)
SLICED_N = 24


def thesis_results_dir(root: Path | None = None) -> Path:
    path = (root or repo_root()) / "results" / "thesis"
    path.mkdir(parents=True, exist_ok=True)
    return path


def refresh_offline_rows(dest: Path | None = None) -> list[dict[str, Any]]:
    """Recompute SAST (raw+sanitized) and retrieval rows. No live LLM.

    Leaves existing LLM trial JSON in place. Used so fair-baseline rows exist
    even when TPD blocks a full thesis rerun.
    """
    dest = dest or thesis_results_dir()
    dest.mkdir(parents=True, exist_ok=True)
    retriever = HybridRetriever.load(allow_download=True)
    research = load_research_corpus(split="research_test")
    trials = [
        trial_sast(research, "research_test", "research"),
        trial_sast(research, "research_test", "research", sanitized=True),
        trial_retrieval_units(retriever, research, "research", "research_test", DISCLAIMER),
    ]
    manifest_path = dest / "juliet_pair_manifest.json"
    if manifest_path.is_file():
        try:
            units = load_juliet_units(require_download=False)
            wanted = set(json.loads(manifest_path.read_text(encoding="utf-8")).get("unit_ids") or [])
            sample = [unit for unit in units if unit.unit_id in wanted]
            if sample:
                trials.extend(
                    [
                        trial_sast(sample, "juliet_pairs", "juliet-pairs"),
                        trial_sast(sample, "juliet_pairs", "juliet-pairs", sanitized=True),
                        trial_retrieval_units(
                            retriever, sample, "juliet-pairs", "juliet_pairs", JULIET_DISCLAIMER
                        ),
                    ]
                )
        except Exception:
            pass
    for trial in trials:
        write_trial(trial, dest)
    _rebuild_summary_from_disk(dest)
    return trials


def _rebuild_summary_from_disk(dest: Path) -> None:
    skip = {
        "summary.json",
        "juliet_pair_manifest.json",
        "vul4j_sliced_manifest.json",
        "human_spotcheck.json",
    }
    trials: list[dict[str, Any]] = []
    for path in sorted(dest.glob("*.json")):
        if path.name in skip or path.name.startswith("Thesis"):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if payload.get("trial_id"):
            trials.append(payload)
    _write_all(trials, dest)


class _Budget:
    """Resume status=ok trials and stop scheduling live LLM work at a token cap."""

    def __init__(self, dest: Path, *, resume: bool, max_tokens: int | None) -> None:
        self.dest = dest
        self.resume = resume
        self.max_tokens = max_tokens
        self.used = 0
        self.blocked = False
        self.block_reason = ""

    def take(self, trial_id: str, factory: Callable[[], dict[str, Any]], *, llm: bool = False) -> dict[str, Any]:
        if self.resume:
            existing = load_ok_trial(self.dest, trial_id)
            if existing is not None:
                copied = dict(existing)
                copied["resumed"] = True
                return copied
        if llm and (self.blocked or (self.max_tokens is not None and self.used >= self.max_tokens)):
            self.blocked = True
            if not self.block_reason:
                self.block_reason = (
                    f"max-tokens {self.max_tokens} (used {self.used})"
                    if self.max_tokens is not None
                    else "prior LLM trial blocked"
                )
            trial = skipped_trial(trial_id, self.block_reason, suite="thesis")
            write_trial(trial, self.dest)
            return trial
        trial = factory()
        self.used += trial_token_count(trial)
        if trial.get("rate_limited"):
            self.blocked = True
            self.block_reason = "rate_limited"
        if self.max_tokens is not None and self.used >= self.max_tokens:
            self.blocked = True
            self.block_reason = f"max-tokens {self.max_tokens} (used {self.used})"
        write_trial(trial, self.dest)
        return trial


def run_thesis_eval(
    *,
    ablation: str = "none",
    juliet_tree: Path | None = None,
    output_dir: Path | None = None,
    pair_per_cwe: int = PAIR_PER_CWE,
    sample_seed: int = SAMPLE_SEED,
    include_model_ablation: bool = False,
    resume: bool = False,
    max_tokens: int | None = None,
) -> list[dict[str, Any]]:
    """C1–C5 (+ optional C7). Stops live LLM work on rate limit / token budget; never template-fills."""
    dest = output_dir or thesis_results_dir()
    dest.mkdir(parents=True, exist_ok=True)
    from cwe_vuln.framework import eval as eval_mod

    eval_mod.RAW_LLM_DIR = dest / "raw_llm"
    eval_mod.REPLAY_RAW_LLM = resume
    retriever = HybridRetriever.load(allow_download=True)
    budget = _Budget(dest, resume=resume, max_tokens=max_tokens)
    trials: list[dict[str, Any]] = []

    research = load_research_corpus(split="research_test")
    trials.append(budget.take("sast_regex_research_test", lambda: trial_sast(research, "research_test", "research"), llm=False))
    trials.append(
        budget.take(
            "sast_regex_sanitized_research_test",
            lambda: trial_sast(research, "research_test", "research", sanitized=True),
            llm=False,
        )
    )
    trials.append(
        budget.take(
            "template_research_test",
            lambda: trial_pipeline(
                "template_research_test",
                research,
                "research_test",
                "research",
                _make_pipeline(retriever, None, skip_llm_when_sast_hits=True, use_llm=False),
                notes="C4 ablation: TemplateReasoner on authored traps. Not the system of record.",
            ),
            llm=False,
        )
    )
    trials.append(
        budget.take(
            "retrieval_units_research_test",
            lambda: trial_retrieval_units(retriever, research, "research", "research_test", DISCLAIMER),
            llm=False,
        )
    )

    llm = None
    model_notes = "ablation=template"
    if ablation != "template":
        llm, model_notes = _llm_with_fallback()
        if llm is None:
            trials.append(
                {
                    "trial_id": "llm_then_research_test",
                    "date": utc_now(),
                    "suite": "research",
                    "status": "failed",
                    "notes": model_notes,
                    "error": model_notes,
                    "metrics": None,
                }
            )
            trials.append(_semgrep_or_skip(None))
            trials.append(_human_spotcheck_placeholder(dest, trials))
            _write_all(trials, dest)
            return trials

    if llm is not None:
        live_c1 = budget.take(
            "llm_then_research_test",
            lambda: trial_pipeline(
                "llm_then_research_test",
                research,
                "research_test",
                "research",
                _make_pipeline(retriever, llm, skip_llm_when_sast_hits=False, use_llm=True),
                notes="C1 sanitized authored traps. System of record. " + model_notes,
                stop_on_rate_limit=True,
                delay_seconds=8.0,
            ),
            llm=True,
        )
        trials.append(live_c1)
        trials.extend(_ablation_trials(research, retriever, llm, model_notes, budget, split="research_test", suite="research"))

    juliet_trials, pair_units, pairs = _juliet_pair_trials(
        retriever,
        llm,
        model_notes,
        tree=juliet_tree,
        per_cwe=pair_per_cwe,
        seed=sample_seed,
        dest=dest,
        budget=budget,
    )
    trials.extend(juliet_trials)

    if llm is not None and pair_units:
        trials.extend(
            _ablation_trials(
                pair_units,
                retriever,
                llm,
                model_notes,
                budget,
                split="juliet_pairs",
                suite="juliet-pairs",
                only_no_retrieval=True,
            )
        )

    if llm is not None:
        trials.extend(_sliced_realworld(retriever, llm, model_notes, dest=dest, budget=budget))
    trials.append(_semgrep_or_skip(pair_units))
    if include_model_ablation and llm is not None:
        trials.extend(_model_ablation(research, retriever, dest=dest, budget=budget))
    trials.append(_human_spotcheck_placeholder(dest, trials))
    _write_all(trials, dest)
    return trials


def _ablation_trials(
    units: list[SeedUnit],
    retriever: HybridRetriever,
    llm: LLMReasoner,
    model_notes: str,
    budget: _Budget,
    *,
    split: str,
    suite: str,
    only_no_retrieval: bool = False,
) -> list[dict[str, Any]]:
    from cwe_vuln.agents import EvidenceAgent, KnowledgeAgent, ReasoningAgent, ValidatorAgent

    no_ret = Pipeline(
        extractor=EvidenceAgent(),
        retriever=EmptyRetriever(),
        reasoner=ReasoningAgent(TemplateReasoner()),
        validator=ValidatorAgent(),
        llm_reasoner=ReasoningAgent(llm),
        skip_llm_when_sast_hits=False,
        use_llm_if_available=True,
    )
    out = [
        budget.take(
            f"llm_no_retrieval_{split}",
            lambda: trial_pipeline(
                f"llm_no_retrieval_{split}",
                units,
                split,
                suite,
                no_ret,
                notes="C4 ablation: LLM + code + SAST, empty CWE hits. " + model_notes,
                stop_on_rate_limit=True,
                delay_seconds=8.0,
            ),
            llm=True,
        )
    ]
    if only_no_retrieval:
        return out
    no_sast = Pipeline(
        extractor=EmptyExtractor(),
        retriever=KnowledgeAgent(retriever),
        reasoner=ReasoningAgent(TemplateReasoner()),
        validator=ValidatorAgent(),
        llm_reasoner=ReasoningAgent(llm),
        skip_llm_when_sast_hits=False,
        use_llm_if_available=True,
    )
    out.append(
        budget.take(
            f"llm_no_sast_{split}",
            lambda: trial_pipeline(
                f"llm_no_sast_{split}",
                units,
                split,
                suite,
                no_sast,
                notes="C4 ablation: LLM + retrieval only, empty SAST evidence. " + model_notes,
                stop_on_rate_limit=True,
                delay_seconds=8.0,
            ),
            llm=True,
        )
    )
    return out


def _juliet_pair_trials(
    retriever: HybridRetriever,
    llm: LLMReasoner | None,
    model_notes: str,
    *,
    tree: Path | None,
    per_cwe: int,
    seed: int,
    dest: Path,
    budget: _Budget,
) -> tuple[list[dict[str, Any]], list[SeedUnit], list[Pair]]:
    try:
        units = load_juliet_units(tree=tree, require_download=tree is None)
    except Exception as exc:
        return (
            [
                {
                    "trial_id": "juliet_pairs",
                    "date": utc_now(),
                    "suite": "juliet-pairs",
                    "status": "failed",
                    "error": str(exc),
                    "metrics": None,
                    "notes": "Juliet tree missing; pair metric not computed.",
                }
            ],
            [],
            [],
        )
    all_pairs = build_pairs(units, exclude_multi_file=False)
    excluded = [
        pair
        for pair in all_pairs
        if is_multi_file_juliet_unit(pair.vulnerable) or is_multi_file_juliet_unit(pair.benign)
    ]
    eligible = build_pairs(units, exclude_multi_file=True)
    pairs = sample_pairs(eligible, per_cwe=per_cwe, seed=seed, cwe_ids=THESIS_FAMILIES)
    sample = flatten_pairs(pairs)
    pair_ids = [p.pair_id for p in pairs]
    old_matches = _c2_cache_matches(dest, pair_ids)
    if not old_matches:
        _archive_multifile_c2_if_needed(dest)
    manifest = {
        "seed": seed,
        "per_cwe": per_cwe,
        "n_pairs": len(pairs),
        "n_units": len(sample),
        "cwe_ids": list(THESIS_FAMILIES),
        "juliet_version": JULIET_VERSION,
        "mapping": mapping_notes(),
        "exclude_multi_file": True,
        "excluded_n_pairs": len(excluded),
        "excluded_pair_ids": [p.pair_id for p in excluded[:200]],
        "multi_file_note": (
            "Juliet _NNa/_NNb flow variants are excluded from this pair pool because "
            "the sink often lives in a sibling file the LLM would never see."
        ),
        "pair_ids": pair_ids,
        "unit_ids": [u.unit_id for u in sample],
    }
    (dest / "juliet_pair_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    saved_resume = budget.resume
    budget.resume = bool(saved_resume and old_matches)
    trials = [
        budget.take("sast_regex_juliet_pairs", lambda: trial_sast(sample, "juliet_pairs", "juliet-pairs"), llm=False),
        budget.take(
            "sast_regex_sanitized_juliet_pairs",
            lambda: trial_sast(sample, "juliet_pairs", "juliet-pairs", sanitized=True),
            llm=False,
        ),
        budget.take(
            "template_juliet_pairs",
            lambda: trial_pipeline(
                "template_juliet_pairs",
                sample,
                "juliet_pairs",
                "juliet-pairs",
                _make_pipeline(retriever, None, skip_llm_when_sast_hits=True, use_llm=False),
                notes="C2 template ablation on the Juliet pair sample.",
                evaluation_scope="juliet_java_v1_3_pair_sample",
                disclaimer=JULIET_DISCLAIMER,
            ),
            llm=False,
        ),
        budget.take(
            "retrieval_units_juliet_pairs",
            lambda: trial_retrieval_units(retriever, sample, "juliet-pairs", "juliet_pairs", JULIET_DISCLAIMER),
            llm=False,
        ),
    ]
    if llm is None:
        budget.resume = saved_resume
        return trials, sample, pairs
    live = budget.take(
        "llm_then_juliet_pairs",
        lambda: _run_c2_llm(sample, pairs, retriever, llm, model_notes, seed),
        llm=True,
    )
    if live.get("status") == "ok" and "pair_metrics" not in live:
        live = _attach_pair_metrics(live, pairs, seed)
    trials.append(live)
    budget.resume = saved_resume
    return trials, sample, pairs


def _run_c2_llm(
    sample: list[SeedUnit],
    pairs: list[Pair],
    retriever: HybridRetriever,
    llm: LLMReasoner,
    model_notes: str,
    seed: int,
) -> dict[str, Any]:
    live = trial_pipeline(
        "llm_then_juliet_pairs",
        sample,
        "juliet_pairs",
        "juliet-pairs",
        _make_pipeline(retriever, llm, skip_llm_when_sast_hits=False, use_llm=True),
        notes="C2 sanitized Juliet good/bad pairs (single-file variants only). " + model_notes,
        delay_seconds=1.5,
        stop_on_rate_limit=True,
        evaluation_scope="juliet_java_v1_3_pair_sample",
        disclaimer=JULIET_DISCLAIMER,
    )
    return _attach_pair_metrics(live, pairs, seed)


def _attach_pair_metrics(live: dict[str, Any], pairs: list[Pair], seed: int) -> dict[str, Any]:
    decisions = {
        row["unit_id"]: row["decision"]
        for row in (live.get("unit_decisions") or [])
        if row.get("decision")
    }
    pair_report = pair_accuracy(pairs, decisions)
    flags = [1.0 if row["correct"] else 0.0 for row in pair_report["pairs"] if not row.get("incomplete")]
    pair_report["bootstrap_95"] = bootstrap_ci(flags, n_boot=1000, seed=seed)
    live["pair_metrics"] = {
        "n_pairs": pair_report["n_pairs"],
        "n_incomplete": pair_report.get("n_incomplete"),
        "correct": pair_report["correct"],
        "accuracy": pair_report["accuracy"],
        "n_abstain": pair_report.get("n_abstain"),
        "abstain_rate": pair_report.get("abstain_rate"),
        "bootstrap_95": pair_report["bootstrap_95"],
        "cwe_502": "not present in Juliet Java 1.3",
        "uncertain_policy": pair_report.get("uncertain_policy"),
    }
    live["pair_rows"] = pair_report["pairs"]
    return live


def _archive_multifile_c2_if_needed(dest: Path) -> None:
    manifest_path = dest / "juliet_pair_manifest.json"
    if not manifest_path.is_file():
        return
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    ids = list(data.get("pair_ids") or []) + list(data.get("unit_ids") or [])
    dirty = not data.get("exclude_multi_file")
    if not dirty:
        for item in ids:
            stripped = re.sub(r"__(method_|file_)?(bad|good[A-Za-z0-9]*)$", "", item or "")
            stripped = re.sub(r"__pair\d+$", "", stripped)
            if MULTI_FILE_STEM.search(stripped):
                dirty = True
                break
    if not dirty:
        return
    archive = dest / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    stamp = "c2_multifile_superseded"
    for name in (
        "juliet_pair_manifest.json",
        "llm_then_juliet_pairs.json",
        "template_juliet_pairs.json",
        "sast_regex_juliet_pairs.json",
        "retrieval_units_juliet_pairs.json",
    ):
        src = dest / name
        if src.is_file():
            shutil.copy2(src, archive / f"{stamp}_{name}")
    note = {
        "status": "superseded",
        "reason": (
            "C2 pair sample included multi-file Juliet variants (_NNa/_NNb) that hide "
            "the sink from the LLM. Kept for audit; not the system of record."
        ),
        "archived_at": utc_now(),
        "original_n_pairs": data.get("n_pairs"),
        "original_pair_ids": data.get("pair_ids"),
    }
    (archive / f"{stamp}.json").write_text(json.dumps(note, indent=2) + "\n", encoding="utf-8")


def _c2_cache_matches(dest: Path, pair_ids: list[str]) -> bool:
    path = dest / "juliet_pair_manifest.json"
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    return bool(data.get("exclude_multi_file")) and list(data.get("pair_ids") or []) == list(pair_ids)


def _sliced_realworld(
    retriever: HybridRetriever,
    llm: LLMReasoner,
    model_notes: str,
    *,
    dest: Path,
    budget: _Budget,
) -> list[dict[str, Any]]:
    name = "vul4j"
    spec = SUITES[name]
    try:
        units = spec.loader(require_download=False)
    except Exception as exc:
        return [
            {
                "trial_id": "llm_then_vul4j_sliced",
                "date": utc_now(),
                "suite": "vul4j-sliced",
                "status": "skipped",
                "error": str(exc),
                "notes": "C3 skipped — Vul4J tree not available locally.",
                "metrics": None,
            }
        ]
    vuln = [u for u in units if u.is_vulnerable]
    fixed = [u for u in units if not u.is_vulnerable]
    half = SLICED_N // 2
    sample = vuln[:half] + fixed[:half]
    sliced = [slice_unit(u, pad=40) for u in sample]
    (dest / "vul4j_sliced_manifest.json").write_text(
        json.dumps({"n": len(sliced), "unit_ids": [u.unit_id for u in sliced]}, indent=2) + "\n",
        encoding="utf-8",
    )
    return [
        budget.take(
            "sast_regex_vul4j_sliced",
            lambda: trial_sast(sliced, "vul4j_sliced", "vul4j-sliced"),
            llm=False,
        ),
        budget.take(
            "llm_then_vul4j_sliced",
            lambda: trial_pipeline(
                "llm_then_vul4j_sliced",
                sliced,
                "vul4j_sliced",
                "vul4j-sliced",
                _make_pipeline(retriever, llm, skip_llm_when_sast_hits=False, use_llm=True),
                notes="C3 sliced Vul4J hunks ±40 lines. " + model_notes,
                delay_seconds=2.0,
                stop_on_rate_limit=True,
                evaluation_scope="vul4j_sliced_hunks",
                disclaimer=spec.disclaimer,
            ),
            llm=True,
        ),
    ]


def _semgrep_or_skip(units: list[SeedUnit] | None) -> dict[str, Any]:
    exe = shutil.which("semgrep")
    if not exe:
        return {
            "trial_id": "semgrep_juliet_pairs",
            "date": utc_now(),
            "suite": "juliet-pairs",
            "status": "skipped",
            "metrics": None,
            "notes": "C5 skipped — semgrep not installed. Not compared to CodeQL (not run).",
            "error": None,
        }
    if not units:
        return {
            "trial_id": "semgrep_juliet_pairs",
            "date": utc_now(),
            "suite": "juliet-pairs",
            "status": "skipped",
            "metrics": None,
            "notes": f"semgrep is installed but the Juliet pair sample was empty. Not compared to CodeQL.",
            "error": None,
        }
    try:
        proc_ver = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False)
        version = (proc_ver.stdout or proc_ver.stderr).strip().splitlines()[0] if (proc_ver.stdout or proc_ver.stderr) else "unknown"
    except OSError as exc:
        version = str(exc)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            files: list[tuple[Path, SeedUnit]] = []
            for unit in units:
                safe = re.sub(r"[^A-Za-z0-9_.-]", "_", unit.unit_id)[:120] + ".java"
                path = tmp_path / safe
                path.write_text(unit.source, encoding="utf-8")
                files.append((path, unit))
            proc = subprocess.run(
                [exe, "--config", "p/java", "--json", "--quiet", str(tmp_path)],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            if proc.returncode not in (0, 1):
                return {
                    "trial_id": "semgrep_juliet_pairs",
                    "date": utc_now(),
                    "suite": "juliet-pairs",
                    "status": "skipped",
                    "metrics": None,
                    "notes": (
                        f"semgrep installed ({version}) but p/java failed "
                        f"(exit {proc.returncode}). Not compared to CodeQL (not run)."
                    ),
                    "error": (proc.stderr or proc.stdout or "")[:500],
                    "semgrep_version": version,
                }
            payload = json.loads(proc.stdout or "{}")
            hits: set[str] = set()
            for finding in payload.get("results") or []:
                path = str(finding.get("path") or "")
                hits.add(Path(path).name)
            y_true = [unit.is_vulnerable for _, unit in files]
            y_pred = [path.name in hits for path, _ in files]
            scores = binary_metrics(y_true, y_pred)
            return {
                "trial_id": "semgrep_juliet_pairs",
                "date": utc_now(),
                "suite": "juliet-pairs",
                "status": "ok",
                "metrics": scores.as_dict(),
                "n_units": len(units),
                "notes": f"C5 semgrep p/java on the Juliet pair sample ({version}). Not compared to CodeQL (not run).",
                "error": None,
                "semgrep_version": version,
            }
    except Exception as exc:
        return {
            "trial_id": "semgrep_juliet_pairs",
            "date": utc_now(),
            "suite": "juliet-pairs",
            "status": "skipped",
            "metrics": None,
            "notes": f"semgrep installed ({version}) but was not scored ({type(exc).__name__}). Not compared to CodeQL.",
            "error": str(exc)[:500],
            "semgrep_version": version,
        }


def _model_ablation(
    units: list[SeedUnit],
    retriever: HybridRetriever,
    *,
    dest: Path,
    budget: _Budget,
) -> list[dict[str, Any]]:
    del dest
    trials: list[dict[str, Any]] = []
    for model in fallback_models():
        if model == settings.llm_model():
            continue
        trial_id = f"llm_{model.replace('/', '_')}_research_test"

        def _run(model_name: str = model, tid: str = trial_id) -> dict[str, Any]:
            built = LLMReasoner.from_env()
            if built is None:
                return skipped_trial(tid, "C7 not run — could not build provider.", suite="research")
            built.model = model_name
            if built.provider is not None:
                built.provider.model = model_name  # type: ignore[attr-defined]
            return trial_pipeline(
                tid,
                units,
                "research_test",
                "research",
                _make_pipeline(retriever, built, skip_llm_when_sast_hits=False, use_llm=True),
                notes=f"C7 model ablation model={model_name}. Same sanitized authored traps.",
                stop_on_rate_limit=True,
            )

        trials.append(budget.take(trial_id, _run, llm=True))
        if trials[-1].get("rate_limited") or trials[-1].get("status") == "skipped":
            break
    if not trials:
        trials.append(
            {
                "trial_id": "llm_model_ablation",
                "date": utc_now(),
                "status": "skipped",
                "notes": "C7 not run — TPD / no extra models.",
                "metrics": None,
                "error": None,
            }
        )
    return trials


def _human_spotcheck_placeholder(dest: Path, trials: list[dict[str, Any]]) -> dict[str, Any]:
    path = dest / "human_spotcheck.json"
    sampled = _sample_spotcheck_rows(trials)
    payload = {
        "status": "not_run",
        "n_target": 30,
        "n_sampled": len(sampled),
        "protocol": (
            "Richa labels 10 correct / 10 FP / 10 FN LLM outputs for explanation "
            "correctness and remediation usefulness. Single rater; no inter-rater stats."
        ),
        "rows": sampled,
        "notes": "C8 not run — awaiting Richa labels. Not filled in. Unit ids are sampled; labels stay empty.",
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return {
        "trial_id": "human_spotcheck",
        "date": utc_now(),
        "status": "skipped",
        "metrics": None,
        "notes": payload["notes"],
        "error": None,
        "path": str(path),
        "n_sampled": len(sampled),
    }


def _gold_labels(trials: list[dict[str, Any]]) -> dict[str, str]:
    gold: dict[str, str] = {}
    try:
        for unit in load_research_corpus(split="research_test"):
            gold[unit.unit_id] = unit.label
    except Exception:
        pass
    for trial in trials:
        for row in trial.get("unit_decisions") or []:
            if row.get("gold_label") and row.get("unit_id"):
                gold[str(row["unit_id"])] = str(row["gold_label"])
        for row in trial.get("pair_rows") or []:
            if row.get("bad_id"):
                gold[str(row["bad_id"])] = "vulnerable"
            if row.get("good_id"):
                gold[str(row["good_id"])] = "not_vulnerable"
    return gold


def _sample_spotcheck_rows(trials: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gold = _gold_labels(trials)
    buckets: dict[str, list[dict[str, Any]]] = {"tp": [], "fp": [], "fn": []}
    for trial in trials:
        if trial.get("trial_id") not in {"llm_then_research_test", "llm_then_juliet_pairs"}:
            continue
        for row in trial.get("unit_decisions") or []:
            unit_id = row.get("unit_id")
            gold_label = row.get("gold_label") or gold.get(unit_id)
            gold_vuln = gold_label == "vulnerable"
            pred = row.get("decision")
            if pred == "vulnerable" and gold_vuln:
                kind = "tp"
            elif pred == "vulnerable" and not gold_vuln:
                kind = "fp"
            elif gold_vuln:
                kind = "fn"
            else:
                continue
            buckets[kind].append(
                {
                    "unit_id": unit_id,
                    "source_trial": trial.get("trial_id"),
                    "gold_label": gold_label,
                    "decision": pred,
                    "predicted_cwe": row.get("predicted_cwe"),
                    "gold_cwe": row.get("gold_cwe"),
                    "explanation_correct": None,
                    "remediation_useful": None,
                }
            )
    rng = random.Random(SAMPLE_SEED)
    selected: list[dict[str, Any]] = []
    for kind in ("tp", "fp", "fn"):
        pool = list(buckets[kind])
        rng.shuffle(pool)
        selected.extend(pool[:10])
    return selected


def _write_all(trials: list[dict[str, Any]], dest: Path) -> None:
    for trial in trials:
        if trial.get("trial_id") == "human_spotcheck" and (dest / "human_spotcheck.json").is_file():
            existing = json.loads((dest / "human_spotcheck.json").read_text(encoding="utf-8"))
            if existing.get("rows") is not None:
                continue
        write_trial(trial, dest)
    detection = [
        item
        for item in trials
        if isinstance(item.get("metrics"), dict) and "precision" in (item.get("metrics") or {})
    ]
    summary = {
        "generated_at": utc_now(),
        "evaluation_scope": "thesis_defendable_eval",
        "disclaimer": (
            "Sanitized prompts. Old public-suite LLM rows (gold-label leakage / silent "
            "Groq fallback) are retracted. Regex SAST on the six named corpora is kept. "
            "Fair SAST contrast is sast_regex_sanitized_*; sast_regex_* is raw disk."
        ),
        "trials": [
            {
                "trial_id": item.get("trial_id"),
                "status": item.get("status"),
                "n_units": item.get("n_units"),
                "n_scored": item.get("n_scored"),
                "metrics": item.get("metrics"),
                "metrics_exclude_abstain": item.get("metrics_exclude_abstain"),
                "abstain_rate": item.get("abstain_rate"),
                "pair_metrics": item.get("pair_metrics"),
                "cwe_exact_match": item.get("cwe_exact_match"),
                "cwe_parent_child_match": item.get("cwe_parent_child_match"),
                "cwe_peer_match": item.get("cwe_peer_match"),
                "cwe_family_match": item.get("cwe_family_match"),
                "cited_lines_rate": item.get("cited_lines_rate"),
                "cited_lines_normalized_rate": item.get("cited_lines_normalized_rate"),
                "rate_limited": item.get("rate_limited"),
                "token_usage": item.get("token_usage"),
                "resumed": item.get("resumed"),
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
                "cwe_exact": item.get("cwe_exact_match"),
                "validation_pass": item.get("validation_pass"),
                "rate_limited": item.get("rate_limited"),
            }
            for item in detection
        ],
    }
    (dest / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Thesis evaluation summary",
        "",
        summary["disclaimer"],
        "",
        f"- Generated: `{summary['generated_at']}`",
        "",
        "| System | Status | Precision | Recall | F1 | FP | FN | n |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary["detection_table"]:
        lines.append(
            f"| {row['system']} | {row.get('status')} | {row['precision']:.3f} | "
            f"{row['recall']:.3f} | {row['f1']:.3f} | {row['fp']} | {row['fn']} | {row['n']} |"
        )
    lines.extend(["", "## Trial log", ""])
    for item in summary["trials"]:
        extra = f" error={item['error']}" if item.get("error") else ""
        pair = item.get("pair_metrics") or {}
        if pair:
            extra += f" pair_acc={pair.get('accuracy')}"
        if item.get("resumed"):
            extra += " resumed"
        lines.append(f"- `{item['trial_id']}` status={item.get('status')} n={item.get('n_units')}{extra}")
    lines.append("")
    (dest / "summary.md").write_text("\n".join(lines), encoding="utf-8")
