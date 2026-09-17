from cwe_vuln.framework import run_split
from cwe_vuln.framework.cli import main as pipeline_main


def test_framework_offline_test_split_has_four_units() -> None:
    report = run_split("test", offline=True)
    assert report["n_units"] == 4
    assert report["split"] == "test"
    assert report["seed_only_not_a_benchmark"] is True
    assert report["offline"] is True
    assert report["validation_pass"] == 4
    assert report["metrics"]["support"] == 4


def test_pipeline_cli_without_key_fails(capsys) -> None:
    code = pipeline_main(["--split", "test"])
    assert code == 1
    captured = capsys.readouterr()
    assert "GROQ_API_KEY" in captured.err
