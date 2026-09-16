from cwe_rag.knowledge import SEED_CWES
from cwe_rag.retrieve import retrieve


def test_sql_query_ranks_cwe_89_first() -> None:
    hits = retrieve("SQL execute SELECT concatenated user id query")
    assert hits, "expected at least one CWE hit"
    assert hits[0].record.cwe_id == "CWE-89"


def test_command_query_ranks_cwe_78_first() -> None:
    hits = retrieve("os.system shell subprocess command injection")
    assert hits[0].record.cwe_id == "CWE-78"


def test_retrieve_empty_query() -> None:
    assert retrieve("   ") == []


def test_seed_kb_covers_four_cwes() -> None:
    ids = {record.cwe_id for record in SEED_CWES}
    assert ids == {"CWE-89", "CWE-79", "CWE-78", "CWE-22"}
