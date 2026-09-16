from cwe_vuln.knowledge import CWEKnowledgeBase, KnowledgeError, SEED_CWE_IDS, normalize_cwe_id
import pytest


def test_load_includes_seed_cwes() -> None:
    kb = CWEKnowledgeBase.load()
    for cwe_id in SEED_CWE_IDS:
        entry = kb.get(cwe_id)
        assert entry.id == cwe_id
        assert entry.name
        assert entry.description
        assert entry.mitigations


def test_normalize_and_get_accept_bare_numbers() -> None:
    assert normalize_cwe_id("89") == "CWE-89"
    kb = CWEKnowledgeBase.load()
    assert kb.get("79").id == "CWE-79"


def test_unknown_id_raises() -> None:
    kb = CWEKnowledgeBase.load()
    with pytest.raises(KnowledgeError):
        kb.get("CWE-99999")


def test_search_finds_sql_injection() -> None:
    kb = CWEKnowledgeBase.load()
    hits = kb.search("sql injection parameterized query")
    assert hits
    assert hits[0][0].id == "CWE-89"


def test_relationships_and_mitigations() -> None:
    kb = CWEKnowledgeBase.load()
    rel = kb.relationships("CWE-798")
    assert "CWE-259" in rel.children
    assert "CWE-287" in rel.parents
    neighbors = {entry.id for entry in kb.neighbors("CWE-798")}
    assert "CWE-259" in neighbors
    mits = kb.mitigations("CWE-22")
    assert any("base directory" in item.text.lower() or "path" in item.title.lower() for item in mits)
