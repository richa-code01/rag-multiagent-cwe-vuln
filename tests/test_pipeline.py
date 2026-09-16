from cwe_rag.pipeline import detect
from cwe_rag.seed_cases import SEED_CASES


def test_each_seed_case_matches_label() -> None:
    for case in SEED_CASES:
        result = detect(case.code)
        assert result.vulnerable is case.vulnerable, case.case_id
        assert result.cwe_id == case.cwe_id, case.case_id


def test_report_includes_retrieved_cwes_for_vulnerable_sql() -> None:
    result = detect('cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)')
    assert result.vulnerable is True
    assert result.cwe_id == "CWE-89"
    assert result.retrieved
    assert result.to_dict()["retrieved"][0]["cwe_id"] == "CWE-89"
