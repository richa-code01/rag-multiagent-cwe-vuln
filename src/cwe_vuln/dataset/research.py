"""Authored research corpus: Assignment 1 seed plus held-out FP/FN traps.

The 12-unit seed and 8/4 split stay in seed.py / data/seed/. This module loads
data/research/labels.jsonl (36 units). Not a public benchmark.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from cwe_vuln.config import SEED_CWE_IDS, repo_root
from cwe_vuln.dataset.seed import (
    TEST_UNIT_IDS,
    TRAIN_UNIT_IDS,
    DatasetError,
    SeedUnit,
    unit_from_payload,
)

ResearchSplit = Literal["all", "seed", "research_test"]

RESEARCH_TEST_UNIT_IDS: tuple[str, ...] = (
    "java_cwe89_t01_comment_concat",
    "java_cwe89_t02_constant_concat",
    "java_cwe89_t03_stringbuilder",
    "java_cwe89_t04_split_concat",
    "java_cwe79_t01_encoded_then_concat",
    "java_cwe79_t02_constant_html",
    "java_cwe79_t03_getparameter",
    "java_cwe79_t04_concat_method",
    "java_cwe22_t01_const_concat",
    "java_cwe22_t02_comment_file",
    "java_cwe22_t03_twoarg_file",
    "java_cwe22_t04_paths_get",
    "java_cwe502_t01_javadoc_objectstream",
    "java_cwe502_t02_roundtrip",
    "java_cwe502_t03_helper_reflection",
    "java_cwe502_t04_xmldecoder_reflect",
    "java_cwe798_t01_sentinel_then_env",
    "java_cwe798_t02_password_log_literal",
    "java_cwe798_t03_char_array",
    "java_cwe798_t04_split_literal",
    "java_cwe327_t01_md5_comment_sha256",
    "java_cwe327_t02_banned_algo_message",
    "java_cwe327_t03_md5_variable",
    "java_cwe327_t04_md5_split_literal",
)

ALLOWED_SPLITS = ("train", "test", "research_test")


def research_labels_path(root: Path | None = None) -> Path:
    return (root or repo_root()) / "data" / "research" / "labels.jsonl"


def load_research_corpus(
    root: Path | None = None,
    split: ResearchSplit = "all",
) -> list[SeedUnit]:
    """Load the authored 36-unit corpus. `split=research_test` is the held-out 24."""
    base = root or repo_root()
    path = research_labels_path(base)
    if not path.is_file():
        raise DatasetError(f"Missing research manifest: {path}")
    records: list[SeedUnit] = []
    seen: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetError(f"Invalid JSON on research labels.jsonl line {line_no}") from exc
            unit = unit_from_payload(payload, base, allowed_splits=ALLOWED_SPLITS)
            if unit.unit_id in seen:
                raise DatasetError(f"Duplicate research unit_id: {unit.unit_id}")
            seen.add(unit.unit_id)
            records.append(unit)
    _validate_research(records)
    seed_ids = set(TRAIN_UNIT_IDS + TEST_UNIT_IDS)
    if split == "seed":
        return [unit for unit in records if unit.unit_id in seed_ids]
    if split == "research_test":
        return [unit for unit in records if unit.split == "research_test"]
    return records


def _validate_research(records: list[SeedUnit]) -> None:
    ids = tuple(unit.unit_id for unit in records)
    expected = TRAIN_UNIT_IDS + TEST_UNIT_IDS + RESEARCH_TEST_UNIT_IDS
    if ids != expected:
        raise DatasetError(
            "research labels.jsonl order/ids must be seed 12 then RESEARCH_TEST_UNIT_IDS. "
            f"got={ids!r} expected={expected!r}"
        )
    if len(records) != 36:
        raise DatasetError(f"Expected 36 authored research units, got {len(records)}")
    research = [unit for unit in records if unit.split == "research_test"]
    if tuple(unit.unit_id for unit in research) != RESEARCH_TEST_UNIT_IDS:
        raise DatasetError("research_test ids drifted from RESEARCH_TEST_UNIT_IDS")
    fp = [unit for unit in research if unit.trap_type == "fp_trap"]
    fn = [unit for unit in research if unit.trap_type == "fn_trap"]
    if len(fp) != 12 or len(fn) != 12:
        raise DatasetError(f"Expected 12 FP and 12 FN traps, got fp={len(fp)} fn={len(fn)}")
    if any(unit.is_vulnerable for unit in fp):
        raise DatasetError("FP traps must be labeled not_vulnerable")
    if any(not unit.is_vulnerable for unit in fn):
        raise DatasetError("FN traps must be labeled vulnerable")
    cwes = {unit.cwe_id for unit in research}
    missing = [cwe for cwe in SEED_CWE_IDS if cwe not in cwes]
    if missing:
        raise DatasetError(f"Research test is missing required CWEs: {missing}")
