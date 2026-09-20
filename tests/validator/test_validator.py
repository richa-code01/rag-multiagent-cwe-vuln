from dataclasses import replace

import pytest

from cwe_vuln.config import MissingLLMKeyError
from cwe_vuln.dataset import load_research_corpus, load_seed
from cwe_vuln.knowledge import CWEKnowledgeBase
from cwe_vuln.models.reasoning import CWERef, ReasoningResult, SourceSpan
from cwe_vuln.reasoner import TemplateReasoner
from cwe_vuln.sast import extract_evidence
from cwe_vuln.validator import ResultValidator


def _vulnerable_override(unit) -> ReasoningResult:
    lines = [line for line in unit.source.splitlines() if line.strip()]
    snippet = lines[0] if lines else " "
    start = unit.source.splitlines().index(snippet) + 1
    entry = CWEKnowledgeBase.load().entries[unit.cwe_id]
    return ReasoningResult(
        unit_id=unit.unit_id,
        decision="vulnerable",
        cwe=CWERef(id=entry.id, name=entry.name),
        supporting_source_lines=SourceSpan(
            path=unit.path,
            start_line=start,
            end_line=start,
            snippet=snippet,
        ),
        root_cause="User-controlled data reaches a sensitive sink.",
        explanation="Regex SAST missed this unit; the sink is still vulnerable.",
        remediation="Constrain the sink and validate the source.",
        confidence=0.8,
    )


def test_vulnerable_result_passes() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    evidence = extract_evidence(unit)
    result = TemplateReasoner().compose(unit, evidence, [])
    report = ResultValidator().check(result, unit, evidence)
    assert report.passed
    assert all(check.passed for check in report.checks)
    assert report.warnings == ()


def test_sast_disagreement_does_not_fail_validator() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    evidence = extract_evidence(unit)
    # Gold evidence exists; a not_vulnerable decision is a warning, not a fail.
    broken = TemplateReasoner().compose(unit, [], [])
    report = ResultValidator().check(broken, unit, evidence)
    assert report.passed
    names = {check.name: check.passed for check in report.checks}
    assert names["schema"] is True
    assert names["internal_consistency"] is True
    assert "decision_consistency" not in names
    assert any(item.name == "sast_disagreement" for item in report.warnings)


def test_vulnerable_without_sast_evidence_passes() -> None:
    unit = next(item for item in load_research_corpus(split="research_test") if item.trap_type == "fn_trap")
    result = _vulnerable_override(unit)
    report = ResultValidator().check(result, unit, [])
    assert report.passed
    assert any(item.name == "sast_disagreement" for item in report.warnings)


def test_empty_explanation_fails_internal_consistency() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    evidence = extract_evidence(unit)
    result = replace(TemplateReasoner().compose(unit, evidence, []), explanation="   ")
    report = ResultValidator().check(result, unit, evidence)
    assert not report.passed
    names = {check.name: check.passed for check in report.checks}
    assert names["internal_consistency"] is False


def test_indent_only_mismatch_fails_raw_cited_lines_but_passes_normalized() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    evidence = extract_evidence(unit)
    template = TemplateReasoner().compose(unit, evidence, [])
    lines = unit.source.splitlines()
    start = end = None
    for index in range(len(lines) - 1):
        if lines[index].strip() and lines[index + 1].strip():
            start, end = index + 1, index + 2
            break
    assert start is not None
    snippet = f"        {lines[start - 1].strip()}\n        {lines[end - 1].strip()}"
    result = replace(
        template,
        supporting_source_lines=replace(
            template.supporting_source_lines,
            start_line=start,
            end_line=end,
            snippet=snippet,
        ),
    )
    report = ResultValidator().check(result, unit, evidence)
    names = {check.name: check.passed for check in report.checks}
    assert names["cited_lines"] is False
    assert names["cited_lines_normalized"] is True
    assert report.passed is False


def test_default_pipeline_requires_groq_key() -> None:
    from cwe_vuln.orchestrator import Pipeline

    with pytest.raises(MissingLLMKeyError, match="GROQ_API_KEY"):
        Pipeline.default()
