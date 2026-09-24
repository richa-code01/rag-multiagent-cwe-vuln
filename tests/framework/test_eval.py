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
    assert trial["sast_input"] == "raw_disk"


def test_sanitized_sast_drops_comment_only_false_positives() -> None:
    units = load_research_corpus(split="research_test")
    raw = trial_sast(units, "research_test", "research")
    sanitized = trial_sast(units, "research_test", "research", sanitized=True)
    assert sanitized["trial_id"] == "sast_regex_sanitized_research_test"
    assert sanitized["sast_input"] == "sanitized"
    assert sanitized["metrics"]["fp"] < raw["metrics"]["fp"]
    assert sanitized["metrics"]["fp"] == 6
    assert "fpr" in sanitized["per_cwe"][units[0].cwe_id]


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


def test_thesis_template_ablation_writes_summary(tmp_path) -> None:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "juliet"
    code = eval_main(
        [
            "--suite",
            "thesis",
            "--ablation",
            "template",
            "--juliet-tree",
            str(fixture),
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    assert (tmp_path / "sast_regex_research_test.json").is_file()
    assert (tmp_path / "summary.json").is_file()
    payload = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert payload["evaluation_scope"] == "thesis_defendable_eval"


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


def test_cwe_tier_splits_exact_parent_and_peer() -> None:
    from cwe_vuln.framework.eval import cwe_tier, enrich_trial_cwe_fields
    from cwe_vuln.knowledge import CWEKnowledgeBase

    kb = CWEKnowledgeBase.load()
    assert cwe_tier("CWE-259", "CWE-259", kb) == "exact"
    assert cwe_tier("CWE-798", "CWE-259", kb) == "parent_child"
    assert cwe_tier("CWE-257", "CWE-259", kb) == "peer"
    assert cwe_tier("CWE-89", "CWE-259", kb) == "none"
    trial = {
        "unit_decisions": [
            {"predicted_cwe": "CWE-259", "gold_cwe": "CWE-259", "decision": "vulnerable"},
            {"predicted_cwe": "CWE-257", "gold_cwe": "CWE-259", "decision": "uncertain"},
            {"predicted_cwe": "CWE-798", "gold_cwe": "CWE-259", "decision": "vulnerable"},
        ]
    }
    enrich_trial_cwe_fields(trial, kb)
    assert trial["cwe_exact_match"] == {"correct": 1, "total": 3}
    assert trial["cwe_peer_match"] == {"correct": 1, "total": 3}
    assert trial["cwe_family_match"] == {"correct": 2, "total": 3}
    assert trial["abstain_n"] == 1


def test_load_ok_trial_resume_helper(tmp_path) -> None:
    from cwe_vuln.framework.eval import load_ok_trial, write_trial

    write_trial({"trial_id": "sast_regex_research_test", "status": "ok", "notes": "keep"}, tmp_path)
    write_trial({"trial_id": "llm_then_research_test", "status": "partial", "notes": "retry"}, tmp_path)
    ok = load_ok_trial(tmp_path, "sast_regex_research_test")
    assert ok is not None and ok["notes"] == "keep"
    assert load_ok_trial(tmp_path, "llm_then_research_test") is None
    assert load_ok_trial(tmp_path, "missing") is None


def test_thesis_resume_does_not_overwrite_ok_trial(tmp_path) -> None:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "juliet"
    args = [
        "--suite",
        "thesis",
        "--ablation",
        "template",
        "--juliet-tree",
        str(fixture),
        "--output-dir",
        str(tmp_path),
    ]
    assert eval_main(args) == 0
    path = tmp_path / "sast_regex_research_test.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["notes"] = "marker-do-not-overwrite"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    assert eval_main([*args, "--resume"]) == 0
    resumed = json.loads(path.read_text(encoding="utf-8"))
    assert resumed["notes"] == "marker-do-not-overwrite"
    assert (tmp_path / "sast_regex_sanitized_research_test.json").is_file()


def test_trial_pipeline_replays_raw_llm_without_calling_provider(tmp_path) -> None:
    from cwe_vuln.agents import EvidenceAgent, ReasoningAgent, ValidatorAgent
    from cwe_vuln.dataset.sanitize import opaque_unit_id
    from cwe_vuln.framework import eval as eval_mod
    from cwe_vuln.framework.eval import trial_pipeline
    from cwe_vuln.knowledge import CWEKnowledgeBase
    from cwe_vuln.orchestrator import Pipeline
    from cwe_vuln.orchestrator.ablations import EmptyRetriever
    from cwe_vuln.reasoner import LLMReasoner, TemplateReasoner

    units = load_research_corpus(split="research_test")[:1]
    unit = units[0]
    line = unit.source.splitlines()[0] if unit.source.splitlines() else "class X {}"
    payload = {
        "schema_version": "1.0",
        "unit_id": unit.unit_id,
        "decision": "vulnerable",
        "cwe": {"id": unit.cwe_id, "name": "replay"},
        "supporting_source_lines": {
            "path": "Snippet.java",
            "start_line": 1,
            "end_line": 1,
            "snippet": line,
        },
        "root_cause": "replay",
        "explanation": "replay",
        "remediation": "replay",
    }

    class BoomProvider:
        name = "boom"
        model = "boom"
        base_url = "https://boom.local"
        api_key = "x"

        def complete(self, messages, *, json_mode=None):
            raise AssertionError("provider must not be called on replay")

    eval_mod.RAW_LLM_DIR = tmp_path / "raw_llm"
    eval_mod.REPLAY_RAW_LLM = True
    dest = eval_mod.RAW_LLM_DIR / "replay_trial"
    dest.mkdir(parents=True)
    (dest / f"{opaque_unit_id(unit.unit_id)}.json").write_text(
        json.dumps(
            {
                "raw_response": json.dumps(payload),
                "usage": {"prompt_tokens": 3, "completion_tokens": 4},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    reasoner = LLMReasoner(provider=BoomProvider(), kb=CWEKnowledgeBase.load())
    pipeline = Pipeline(
        extractor=EvidenceAgent(),
        retriever=EmptyRetriever(),
        reasoner=ReasoningAgent(TemplateReasoner()),
        validator=ValidatorAgent(),
        llm_reasoner=ReasoningAgent(reasoner),
        skip_llm_when_sast_hits=False,
        use_llm_if_available=True,
    )
    try:
        trial = trial_pipeline("replay_trial", units, "research_test", "research", pipeline, "replay")
    finally:
        eval_mod.REPLAY_RAW_LLM = False
        eval_mod.RAW_LLM_DIR = None
    assert trial["status"] == "ok"
    assert trial["replayed_n"] == 1
    assert trial["n_scored"] == 1
    assert trial["unit_decisions"][0]["decision"] == "vulnerable"
