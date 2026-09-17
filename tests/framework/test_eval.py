from pathlib import Path
import json

from cwe_vuln.dataset import load_research_corpus
from cwe_vuln.framework.eval import main as eval_main
from cwe_vuln.framework.eval import trial_sast, write_summary


def test_sast_research_trial_is_imperfect() -> None:
    units = load_research_corpus(split="research_test")
    trial = trial_sast(units, "research_test", "research")
    assert trial["status"] == "ok"
    assert trial["n_units"] == 24
    assert trial["evaluation_scope"] == "authored_corpus_not_a_public_benchmark"
    metrics = trial["metrics"]
    assert metrics["fp"] == 12
    assert metrics["fn"] == 12
    assert metrics["f1"] < 1.0


def test_write_summary_roundtrip(tmp_path) -> None:
    units = load_research_corpus(split="research_test")
    trial = trial_sast(units, "research_test", "research")
    json_path, md_path = write_summary([trial], root=tmp_path)
    assert json_path.is_file()
    assert md_path.is_file()
    assert "not a public benchmark" in md_path.read_text(encoding="utf-8")


def test_eval_cli_without_key_fails(capsys) -> None:
    code = eval_main(["--suite", "research"])
    assert code == 1
    captured = capsys.readouterr()
    assert "GROQ_API_KEY" in captured.err


def test_eval_template_ablation_does_not_require_key(tmp_path) -> None:
    code = eval_main(["--suite", "research", "--ablation", "template", "--output-dir", str(tmp_path)])
    assert code == 0
    assert (tmp_path / "sast_regex_research_test.json").is_file()
    assert (tmp_path / "template_skip_llm_research_test.json").is_file()
    assert not (tmp_path / "llm_then_research_test.json").is_file()


def test_juliet_sast_cli_on_fixture(tmp_path) -> None:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "juliet"
    code = eval_main(
        [
            "--suite",
            "juliet-sast",
            "--juliet-tree",
            str(fixture),
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    payload = json.loads((tmp_path / "sast_regex_juliet.json").read_text(encoding="utf-8"))
    assert payload["trial_id"] == "sast_regex_juliet"
    assert payload["n_units"] >= 4
    assert payload["evaluation_scope"] == "juliet_java_v1_3_mapped_subset"
    assert payload["metrics"]["support"] == payload["n_units"]
