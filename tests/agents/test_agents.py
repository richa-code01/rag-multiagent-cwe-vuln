"""Named agents and ApproachDoc stage signals (risk, coverage, fused confidence)."""

from cwe_vuln.agents import EvidenceAgent, KnowledgeAgent, ReasoningAgent, ValidatorAgent
from cwe_vuln.dataset import load_seed
from cwe_vuln.models.retrieval import RankedHit
from cwe_vuln.orchestrator import Pipeline
from cwe_vuln.orchestrator.confidence import fuse_confidence, risk_score
from cwe_vuln.reasoner import TemplateReasoner
from cwe_vuln.reasoner.prompts import render_prompt
from cwe_vuln.validator import ResultValidator


def test_offline_pipeline_records_stage_signals() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    out = Pipeline.offline().run(unit)
    assert out.risk_score > 0
    assert 0.0 <= out.retrieval_confidence <= 1.0
    assert 0.0 <= out.final_confidence <= 1.0
    assert out.hits
    assert any(getattr(hit, "passage", "") for hit in out.hits), "RAG hits must carry CWE prose"


def test_prompt_includes_retrieved_cwe_passage() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    hits = [
        RankedHit(
            cwe_id="CWE-89",
            score=0.9,
            name="SQL Injection",
            passage="The product constructs all or part of an SQL command using externally-influenced input.",
        )
    ]
    rendered = render_prompt(unit, [], hits)
    assert "SQL command" in rendered.text
    assert "passage" in rendered.text


def test_knowledge_agent_coverage_and_confidence() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    evidence = EvidenceAgent().extract(unit)
    agent = KnowledgeAgent()
    hits = agent.rank_for_unit(unit)
    assert hits
    conf = agent.retrieval_confidence(unit)
    assert 0.0 <= conf <= 1.0
    cov = agent.coverage(evidence, hits)
    assert cov is not None
    assert cov >= 0.0


def test_named_agents_compose_offline_pipeline() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    pipeline = Pipeline(
        extractor=EvidenceAgent(),
        retriever=KnowledgeAgent(),
        reasoner=ReasoningAgent(TemplateReasoner()),
        validator=ValidatorAgent(),
    )
    out = pipeline.run(unit)
    assert out.result.decision == "vulnerable"
    assert out.report.passed
    assert out.reasoner == "template"


def test_risk_score_and_fusion_bounds() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    evidence = EvidenceAgent().extract(unit)
    assert risk_score([]) == 0.0
    assert risk_score(evidence) == 0.5
    result = TemplateReasoner().reason(unit, evidence, [])
    report = ResultValidator().check(result, unit, evidence)
    fused = fuse_confidence(result, evidence, retrieval_confidence=0.8, report=report)
    assert 0.0 <= fused <= 1.0
