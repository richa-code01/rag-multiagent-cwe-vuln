"""Load the Assignment 1 authored Java seed and its deterministic split."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Split = Literal["train", "test"]
Label = Literal["vulnerable", "not_vulnerable"]

# Explicit 8/4 split. Order is stable and is the source of truth (not shuffled).
TRAIN_UNIT_IDS: tuple[str, ...] = (
    "java_cwe89_sqli_concat",
    "java_cwe89_sqli_prepared",
    "java_cwe79_xss_unescaped",
    "java_cwe79_xss_encoded",
    "java_cwe22_path_concat",
    "java_cwe22_path_resolved",
    "java_cwe502_readobject",
    "java_cwe502_json_parse",
)

TEST_UNIT_IDS: tuple[str, ...] = (
    "java_cwe798_hardcoded",
    "java_cwe798_env_config",
    "java_cwe327_md5",
    "java_cwe327_sha256",
)

EXPECTED_CWES: tuple[str, ...] = (
    "CWE-89",
    "CWE-79",
    "CWE-22",
    "CWE-502",
    "CWE-798",
    "CWE-327",
)


@dataclass(frozen=True)
class SeedUnit:
    unit_id: str
    cwe_id: str
    path: str
    split: Split
    label: Label
    notes: str
    source: str

    @property
    def is_vulnerable(self) -> bool:
        return self.label == "vulnerable"


class DatasetError(RuntimeError):
    """Raised when the seed manifest and on-disk files are inconsistent."""


def repo_root(start: Path | None = None) -> Path:
    """Walk parents until `data/seed/labels.jsonl` is found."""
    cursor = (start or Path(__file__).resolve()).parent
    for path in [cursor, *cursor.parents]:
        if (path / "data" / "seed" / "labels.jsonl").exists():
            return path
    raise DatasetError("Could not locate data/seed/labels.jsonl from the package path.")


def labels_path(root: Path | None = None) -> Path:
    return (root or repo_root()) / "data" / "seed" / "labels.jsonl"


def load_seed(root: Path | None = None, split: Split | Literal["all"] = "all") -> list[SeedUnit]:
    """Load labeled Java units. `split` filters to train, test, or all units."""
    base = root or repo_root()
    records: list[SeedUnit] = []
    seen: set[str] = set()
    with labels_path(base).open(encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetError(f"Invalid JSON on labels.jsonl line {line_no}") from exc
            unit = _unit_from_payload(payload, base)
            if unit.unit_id in seen:
                raise DatasetError(f"Duplicate unit_id: {unit.unit_id}")
            seen.add(unit.unit_id)
            records.append(unit)

    _validate(records)

    if split == "all":
        return records
    return [unit for unit in records if unit.split == split]


def _unit_from_payload(payload: dict[str, object], root: Path) -> SeedUnit:
    required = ("unit_id", "cwe_id", "path", "split", "label", "notes")
    missing = [key for key in required if key not in payload]
    if missing:
        raise DatasetError(f"Label record missing fields: {missing}")

    split = payload["split"]
    label = payload["label"]
    if split not in ("train", "test"):
        raise DatasetError(f"Invalid split for {payload.get('unit_id')!r}: {split!r}")
    if label not in ("vulnerable", "not_vulnerable"):
        raise DatasetError(f"Invalid label for {payload.get('unit_id')!r}: {label!r}")

    relative = Path(str(payload["path"]))
    source_path = root / relative
    if not source_path.is_file():
        raise DatasetError(f"Missing Java unit file: {relative}")

    return SeedUnit(
        unit_id=str(payload["unit_id"]),
        cwe_id=str(payload["cwe_id"]),
        path=str(payload["path"]),
        split=split,
        label=label,
        notes=str(payload["notes"]),
        source=source_path.read_text(encoding="utf-8"),
    )


def _validate(records: list[SeedUnit]) -> None:
    ids = tuple(unit.unit_id for unit in records)
    expected = TRAIN_UNIT_IDS + TEST_UNIT_IDS
    if ids != expected:
        raise DatasetError(
            "labels.jsonl order/ids must match TRAIN_UNIT_IDS + TEST_UNIT_IDS. "
            f"got={ids!r} expected={expected!r}"
        )
    if len(TRAIN_UNIT_IDS) != 8 or len(TEST_UNIT_IDS) != 4:
        raise DatasetError("Expected an explicit 8/4 train/test split.")
    for unit in records:
        if unit.unit_id in TRAIN_UNIT_IDS and unit.split != "train":
            raise DatasetError(f"{unit.unit_id} must be split=train")
        if unit.unit_id in TEST_UNIT_IDS and unit.split != "test":
            raise DatasetError(f"{unit.unit_id} must be split=test")
    cwes = {unit.cwe_id for unit in records}
    missing = [cwe for cwe in EXPECTED_CWES if cwe not in cwes]
    if missing:
        raise DatasetError(f"Seed is missing required CWEs: {missing}")
