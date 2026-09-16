from pathlib import Path

from cwe_rag.cli import main


def test_eval_cli_prints_seed_f1(capsys) -> None:
    assert main(["eval"]) == 0
    out = capsys.readouterr().out
    assert '"f1": 1.0' in out
    assert "seed-only" in out


def test_detect_cli_file(tmp_path: Path, capsys) -> None:
    snippet = tmp_path / "sample.py"
    snippet.write_text("os.system('ping ' + host)\n")
    assert main(["detect", "--file", str(snippet)]) == 0
    out = capsys.readouterr().out
    assert "CWE-78" in out
    assert '"vulnerable": true' in out
