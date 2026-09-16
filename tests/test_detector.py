from cwe_vuln.dataset import load_seed
from cwe_vuln.detector import Detection, detect, match_rules


def test_detect_returns_prediction_object() -> None:
    unit = load_seed()[0]
    prediction = detect(unit)
    assert isinstance(prediction, Detection)
    assert prediction.unit_id == unit.unit_id
    assert prediction.predicted_label in {"vulnerable", "not_vulnerable"}
    assert isinstance(prediction.predicted_cwes, tuple)
    assert isinstance(prediction.matched_rules, tuple)


def test_sql_concat_unit_is_flagged() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    prediction = detect(unit)
    assert prediction.predicted_label == "vulnerable"
    assert "CWE-89" in prediction.predicted_cwes
    assert "sql_string_concat" in prediction.matched_rules


def test_prepared_statement_unit_is_not_flagged() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_prepared")
    prediction = detect(unit)
    assert prediction.predicted_label == "not_vulnerable"
    assert prediction.matched_rules == ()


def test_match_rules_on_inline_snippets() -> None:
    sql = match_rules('String q = "SELECT * FROM t WHERE id = \'" + id;')
    assert any(item.cwe_id == "CWE-89" for item in sql)
    sha = match_rules('MessageDigest.getInstance("SHA-256")')
    assert sha == []
