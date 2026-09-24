"""Pair metric + bootstrap unit tests (no live LLM)."""

from cwe_vuln.dataset.seed import SeedUnit
from cwe_vuln.framework.pairs import bootstrap_ci, build_pairs, pair_accuracy, sample_pairs


def _unit(uid: str, label: str, cwe: str = "CWE-89") -> SeedUnit:
    return SeedUnit(
        unit_id=uid,
        cwe_id=cwe,
        path=f"{uid}.java",
        split="juliet",
        label=label,  # type: ignore[arg-type]
        notes="",
        source="class X {}",
    )


def test_build_and_score_pairs() -> None:
    units = [
        _unit("juliet_CWE89_file__method_bad", "vulnerable"),
        _unit("juliet_CWE89_file__method_good1", "not_vulnerable"),
        _unit("juliet_CWE89_other__method_bad", "vulnerable"),
        _unit("juliet_CWE89_other__method_goodB2G", "not_vulnerable"),
    ]
    pairs = build_pairs(units)
    assert len(pairs) == 2
    decisions = {
        "juliet_CWE89_file__method_bad": "vulnerable",
        "juliet_CWE89_file__method_good1": "not_vulnerable",
        "juliet_CWE89_other__method_bad": "vulnerable",
        "juliet_CWE89_other__method_goodB2G": "vulnerable",  # FP on the good method
    }
    report = pair_accuracy(pairs, decisions)
    assert report["n_pairs"] == 2
    assert report["correct"] == 1
    assert report["accuracy"] == 0.5


def test_sample_pairs_is_deterministic() -> None:
    units = []
    for i in range(8):
        units.append(_unit(f"juliet_CWE89_f{i}__method_bad", "vulnerable"))
        units.append(_unit(f"juliet_CWE89_f{i}__method_good1", "not_vulnerable"))
    pairs = build_pairs(units)
    a = sample_pairs(pairs, per_cwe=3, seed=13)
    b = sample_pairs(pairs, per_cwe=3, seed=13)
    assert [p.pair_id for p in a] == [p.pair_id for p in b]
    assert len(a) == 3


def test_bootstrap_ci_covers_mean() -> None:
    values = [1.0, 1.0, 1.0, 0.0, 1.0, 0.0]
    ci = bootstrap_ci(values, n_boot=200, seed=7)
    assert ci["n"] == 6
    assert ci["low"] <= ci["mean"] <= ci["high"]
    assert 0.0 <= ci["low"] <= 1.0


def test_multi_file_juliet_stems_are_excluded_from_pairs() -> None:
    units = [
        _unit(
            "juliet_CWE259_CWE259_Hard_Coded_Password__driverManager_81a__method_bad",
            "vulnerable",
            "CWE-259",
        ),
        _unit(
            "juliet_CWE259_CWE259_Hard_Coded_Password__driverManager_81a__method_goodG2B",
            "not_vulnerable",
            "CWE-259",
        ),
        _unit("juliet_CWE89_single__method_bad", "vulnerable"),
        _unit("juliet_CWE89_single__method_good1", "not_vulnerable"),
    ]
    pairs = build_pairs(units)
    assert [p.pair_id for p in pairs] == ["juliet_CWE89_single__pair0"]
    included = build_pairs(units, exclude_multi_file=False)
    assert len(included) == 2


def test_uncertain_is_pair_incorrect_and_counted() -> None:
    units = [
        _unit("juliet_CWE89_file__method_bad", "vulnerable"),
        _unit("juliet_CWE89_file__method_good1", "not_vulnerable"),
    ]
    pairs = build_pairs(units)
    report = pair_accuracy(
        pairs,
        {
            "juliet_CWE89_file__method_bad": "uncertain",
            "juliet_CWE89_file__method_good1": "not_vulnerable",
        },
    )
    assert report["correct"] == 0
    assert report["n_abstain"] == 1
    assert report["abstain_rate"] == 1.0


def test_incomplete_pair_is_excluded_from_accuracy() -> None:
    units = [
        _unit("juliet_CWE89_file__method_bad", "vulnerable"),
        _unit("juliet_CWE89_file__method_good1", "not_vulnerable"),
        _unit("juliet_CWE89_other__method_bad", "vulnerable"),
        _unit("juliet_CWE89_other__method_good1", "not_vulnerable"),
    ]
    pairs = build_pairs(units)
    report = pair_accuracy(
        pairs,
        {
            "juliet_CWE89_file__method_bad": "vulnerable",
            "juliet_CWE89_file__method_good1": "not_vulnerable",
            "juliet_CWE89_other__method_bad": "vulnerable",
        },
    )
    assert report["n_incomplete"] == 1
    assert report["n_pairs"] == 1
    assert report["correct"] == 1
    assert report["accuracy"] == 1.0
