from cwe_vuln.dataset import load_research_corpus
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
