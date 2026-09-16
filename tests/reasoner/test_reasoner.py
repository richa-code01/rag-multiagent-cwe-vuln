from cwe_vuln.dataset import load_seed
from cwe_vuln.reasoner import TemplateReasoner
from cwe_vuln.retrieval import HybridRetriever, RetrievalQuery
from cwe_vuln.sast import extract_evidence
from cwe_vuln.schema import is_valid


def test_vulnerable_unit_is_schema_valid() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    result = TemplateReasoner().compose(unit, extract_evidence(unit), [])
    assert result.decision == "vulnerable"
    assert result.cwe.id == "CWE-89"
    assert result.evidence_ids
    assert is_valid(result.to_dict())


def test_safe_unit_is_not_vulnerable() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_prepared")
    retriever = HybridRetriever.load()
    query = RetrievalQuery(query_id=unit.unit_id, query=unit.notes, relevant_cwes=(), unit_id=unit.unit_id)
    hits = retriever.hybrid_rank(query)
    result = TemplateReasoner().compose(unit, extract_evidence(unit), hits)
    assert result.decision == "not_vulnerable"
    assert result.evidence_ids == ()
    assert is_valid(result.to_dict())
