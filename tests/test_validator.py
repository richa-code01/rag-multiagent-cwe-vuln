from cwe_vuln.dataset import load_seed
from cwe_vuln.evidence import extract_evidence
from cwe_vuln.reasoner import TemplateReasoner
from cwe_vuln.validator import ResultValidator


def test_vulnerable_result_passes() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    evidence = extract_evidence(unit)
    result = TemplateReasoner().compose(unit, evidence, [])
    report = ResultValidator().check(result, unit, evidence)
    assert report.passed
    assert all(check.passed for check in report.checks)


def test_decision_mismatch_fails() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    evidence = extract_evidence(unit)
    result = TemplateReasoner().compose(unit, evidence, [])
    # Gold evidence exists; a not_vulnerable decision must fail consistency.
    broken = TemplateReasoner().compose(unit, [], [])
    report = ResultValidator().check(broken, unit, evidence)
    assert not report.passed
    names = {check.name: check.passed for check in report.checks}
    assert names["decision_consistency"] is False
