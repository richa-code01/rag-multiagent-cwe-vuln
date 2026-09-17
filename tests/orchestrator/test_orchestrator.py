from cwe_vuln.config import Settings
from cwe_vuln.dataset import load_seed
from cwe_vuln.orchestrator import Pipeline
from cwe_vuln.reasoner import TemplateReasoner
from cwe_vuln.retrieval import HybridRetriever
from cwe_vuln.sast import RegexEvidenceExtractor
from cwe_vuln.validator import ResultValidator


def test_pipeline_logs_sast_first_on_vuln_unit() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    pipeline = Pipeline.default()
    out = pipeline.run(unit)
    assert out.path.startswith("sast_first")
    assert out.result.decision == "vulnerable"
    assert out.report.passed
    assert out.evidence
    assert pipeline.llm_reasoner is None
    assert out.reasoner == "template"


def test_pipeline_skips_llm_on_safe_unit() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_prepared")
    out = Pipeline.default().run(unit)
    assert "skip_llm" in out.path
    assert out.result.decision == "not_vulnerable"
    assert out.report.passed
    assert out.reasoner == "template"


def test_pipeline_routes_to_llm_when_key_present(monkeypatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    template = TemplateReasoner()
    calls = {"n": 0}

    class StubLLM:
        last_backend = "llm"

        def reason(self, unit, evidence, hits):
            calls["n"] += 1
            self.last_backend = "llm"
            return template.reason(unit, evidence, hits)

    pipeline = Pipeline(
        extractor=RegexEvidenceExtractor(),
        retriever=HybridRetriever.load(),
        reasoner=template,
        validator=ResultValidator(),
        llm_reasoner=StubLLM(),
    )
    out = pipeline.run(unit)
    assert out.path == "sast_then_llm"
    assert calls["n"] == 1
    assert out.reasoner == "llm"
    assert out.report.passed


def test_pipeline_can_skip_llm_when_sast_hits(monkeypatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    monkeypatch.setattr(
        "cwe_vuln.orchestrator.pipeline.settings",
        Settings(use_llm_if_available=True, skip_llm_when_sast_hits=True),
    )
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    calls = {"n": 0}

    class StubLLM:
        last_backend = "llm"

        def reason(self, unit, evidence, hits):
            calls["n"] += 1
            return TemplateReasoner().reason(unit, evidence, hits)

    pipeline = Pipeline(
        extractor=RegexEvidenceExtractor(),
        retriever=HybridRetriever.load(),
        reasoner=TemplateReasoner(),
        validator=ResultValidator(),
        llm_reasoner=StubLLM(),
    )
    out = pipeline.run(unit)
    assert out.path == "sast_first_skip_llm"
    assert calls["n"] == 0
    assert out.reasoner == "template"
