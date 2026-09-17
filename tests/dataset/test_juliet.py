from pathlib import Path

from cwe_vuln.dataset.juliet import load_juliet_units, stratified_sample

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "juliet"


def test_mixed_file_splits_good_and_bad() -> None:
    units = load_juliet_units(tree=FIXTURE)
    mixed = [unit for unit in units if "fixture_01" in unit.unit_id]
    kinds = {}
    for unit in mixed:
        kind = unit.unit_id.rsplit("__", 1)[-1]
        kinds[kind] = unit.label
    assert kinds["method_bad"] == "vulnerable"
    assert kinds["method_goodG2B"] == "not_vulnerable"
    assert kinds["method_goodB2G"] == "not_vulnerable"
    assert "method_good" not in kinds
    assert all("public void good()" not in unit.source for unit in mixed)


def test_filename_bad_and_good_and_skips_base() -> None:
    units = load_juliet_units(tree=FIXTURE)
    ids = {unit.unit_id: unit.label for unit in units}
    assert any(uid.endswith("__file_bad") and label == "vulnerable" for uid, label in ids.items())
    assert any(uid.endswith("__file_good") and label == "not_vulnerable" for uid, label in ids.items())
    assert not any("_base" in uid for uid in ids)
    assert all(unit.cwe_id == "CWE-89" for unit in units)
    assert all(unit.corpus == "juliet" for unit in units)


def test_stratified_sample_is_deterministic() -> None:
    units = load_juliet_units(tree=FIXTURE)
    first = [unit.unit_id for unit in stratified_sample(units, per_cwe=4, seed=13)]
    second = [unit.unit_id for unit in stratified_sample(units, per_cwe=4, seed=13)]
    assert first == second
    assert first
