from cwe_vuln.framework import run_split


def test_framework_test_split_has_four_units() -> None:
    report = run_split("test")
    assert report["n_units"] == 4
    assert report["split"] == "test"
    assert report["seed_only_not_a_benchmark"] is True
    assert report["validation_pass"] == 4
    assert report["metrics"]["support"] == 4
