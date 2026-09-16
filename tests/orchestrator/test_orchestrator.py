from cwe_vuln.dataset import load_seed
from cwe_vuln.orchestrator import Pipeline


def test_pipeline_logs_sast_first_on_vuln_unit() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    out = Pipeline.default().run(unit)
    assert out.path.startswith("sast_first")
    assert out.result.decision == "vulnerable"
    assert out.report.passed
    assert out.evidence


def test_pipeline_skips_llm_on_safe_unit() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_prepared")
    out = Pipeline.default().run(unit)
    assert "skip_llm" in out.path or "unimplemented" in out.path
    assert out.result.decision == "not_vulnerable"
    assert out.report.passed
