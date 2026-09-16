from cwe_vuln.dataset import load_seed
from cwe_vuln.evidence import extract_evidence


def test_vulnerable_sql_unit_emits_cwe89_span() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    hits = extract_evidence(unit)
    assert hits
    assert hits[0].cwe_id == "CWE-89"
    assert hits[0].rule_id == "sql_string_concat"
    assert hits[0].path.endswith("Cwe89SqlConcatVulnerable.java")
    assert hits[0].start_line >= 1
    assert "SELECT" in hits[0].snippet
    assert hits[0].rationale


def test_safe_sql_unit_has_no_evidence() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_prepared")
    assert extract_evidence(unit) == []
