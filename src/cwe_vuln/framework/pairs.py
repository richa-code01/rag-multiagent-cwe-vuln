"""Pairwise Juliet metrics and bootstrap CIs. No extra dependencies."""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import Any

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.dataset.juliet import is_multi_file_juliet_unit

_KIND = re.compile(r"__(method_|file_)?(bad|good[A-Za-z0-9]*)$")


@dataclass(frozen=True)
class Pair:
    """One Juliet good/bad counterpart pair (same file stem, opposite labels)."""

    pair_id: str
    cwe_id: str
    vulnerable: SeedUnit
    benign: SeedUnit


def pair_key(unit: SeedUnit) -> str:
    """Group method_bad / method_good* (or file_bad / file_good) from one stem."""
    uid = unit.unit_id
    stripped = _KIND.sub("", uid)
    return stripped or unit.path


def build_pairs(units: list[SeedUnit], *, exclude_multi_file: bool = True) -> list[Pair]:
    """Match each vulnerable unit with one benign counterpart sharing the stem.

    Multi-file Juliet variants (``_81a`` / ``_68b``) are excluded by default:
    the sink often lives in a sibling file the unit source does not include.
    """
    grouped: dict[str, dict[str, list[SeedUnit]]] = {}
    for unit in units:
        if exclude_multi_file and is_multi_file_juliet_unit(unit):
            continue
        bucket = grouped.setdefault(pair_key(unit), {"vulnerable": [], "not_vulnerable": []})
        bucket[unit.label].append(unit)
    pairs: list[Pair] = []
    for key, bucket in grouped.items():
        bads = bucket["vulnerable"]
        goods = bucket["not_vulnerable"]
        n = min(len(bads), len(goods))
        for index in range(n):
            bad = bads[index]
            good = goods[index]
            pairs.append(
                Pair(
                    pair_id=f"{key}__pair{index}",
                    cwe_id=bad.cwe_id,
                    vulnerable=bad,
                    benign=good,
                )
            )
    pairs.sort(key=lambda item: item.pair_id)
    return pairs


def sample_pairs(
    pairs: list[Pair],
    *,
    per_cwe: int = 6,
    seed: int = 13,
    cwe_ids: tuple[str, ...] | None = None,
) -> list[Pair]:
    rng = random.Random(seed)
    pool = [pair for pair in pairs if cwe_ids is None or pair.cwe_id in cwe_ids]
    by_cwe: dict[str, list[Pair]] = {}
    for pair in pool:
        by_cwe.setdefault(pair.cwe_id, []).append(pair)
    sampled: list[Pair] = []
    for cwe_id in sorted(by_cwe):
        group = list(by_cwe[cwe_id])
        rng.shuffle(group)
        sampled.extend(group[:per_cwe])
    sampled.sort(key=lambda item: item.pair_id)
    return sampled


def flatten_pairs(pairs: list[Pair]) -> list[SeedUnit]:
    units: list[SeedUnit] = []
    for pair in pairs:
        units.append(pair.vulnerable)
        units.append(pair.benign)
    return units


def pair_accuracy(pairs: list[Pair], decisions: dict[str, str]) -> dict[str, Any]:
    """A pair is correct only if bad → vulnerable AND good → not_vulnerable.

    Pairs missing either decision (TPD abort) are listed as incomplete and are
    **not** counted in accuracy. `uncertain` on a complete pair is incorrect.
    """
    rows: list[dict[str, Any]] = []
    for pair in pairs:
        bad_dec = decisions.get(pair.vulnerable.unit_id, "")
        good_dec = decisions.get(pair.benign.unit_id, "")
        incomplete = not bad_dec or not good_dec
        ok = (not incomplete) and bad_dec == "vulnerable" and good_dec == "not_vulnerable"
        rows.append(
            {
                "pair_id": pair.pair_id,
                "cwe_id": pair.cwe_id,
                "bad_id": pair.vulnerable.unit_id,
                "good_id": pair.benign.unit_id,
                "bad_decision": bad_dec,
                "good_decision": good_dec,
                "correct": ok,
                "incomplete": incomplete,
            }
        )
    scored = [row for row in rows if not row["incomplete"]]
    n = len(scored)
    n_incomplete = len(rows) - n
    correct = sum(1 for row in scored if row["correct"])
    n_abstain = sum(
        1
        for row in scored
        if row["bad_decision"] == "uncertain" or row["good_decision"] == "uncertain"
    )
    return {
        "n_pairs": n,
        "n_incomplete": n_incomplete,
        "correct": correct,
        "accuracy": (correct / n) if n else 0.0,
        "n_abstain": n_abstain,
        "abstain_rate": (n_abstain / n) if n else 0.0,
        "pairs": rows,
        "uncertain_policy": (
            "A pair with any `uncertain` decision is incorrect. Binary metrics "
            "report abstain-as-negative and exclude-abstain separately. "
            "Pairs missing a decision (TPD) are incomplete and excluded from accuracy."
        ),
    }


def bootstrap_ci(
    values: list[float],
    *,
    n_boot: int = 1000,
    seed: int = 13,
    alpha: float = 0.05,
) -> dict[str, float]:
    """Percentile bootstrap CI over a list of 0/1 (or other) observations."""
    if not values:
        return {"mean": 0.0, "low": 0.0, "high": 0.0, "n": 0, "n_boot": n_boot}
    rng = random.Random(seed)
    n = len(values)
    means: list[float] = []
    for _ in range(n_boot):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    lo_idx = int(alpha / 2 * n_boot)
    hi_idx = int((1 - alpha / 2) * n_boot) - 1
    hi_idx = max(0, min(n_boot - 1, hi_idx))
    return {
        "mean": round(sum(values) / n, 4),
        "low": round(means[lo_idx], 4),
        "high": round(means[hi_idx], 4),
        "n": n,
        "n_boot": n_boot,
    }
