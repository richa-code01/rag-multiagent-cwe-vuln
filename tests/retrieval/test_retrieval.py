from cwe_vuln.retrieval import (
    HybridRetriever,
    RetrievalQuery,
    TfidfIndex,
    load_retrieval_queries,
    mean_reciprocal_rank,
    recall_at_k,
    rrf_combine,
)


def test_rrf_prefers_consensus() -> None:
    fused = rrf_combine(["CWE-89", "CWE-79"], ["CWE-89", "CWE-22"])
    assert fused[0][0] == "CWE-89"


def test_recall_and_mrr_helpers() -> None:
    ranked = ["CWE-79", "CWE-89", "CWE-22"]
    assert recall_at_k(["CWE-89"], ranked, 1) == 0.0
    assert recall_at_k(["CWE-89"], ranked, 2) == 1.0
    assert mean_reciprocal_rank(["CWE-89"], ranked) == 0.5


def test_tfidf_ranks_matching_document() -> None:
    index = TfidfIndex(
        {
            "CWE-89": "sql injection concatenated query statement",
            "CWE-79": "html cross site scripting output encode",
        }
    )
    hits = index.rank("sql injection query")
    assert hits[0].cwe_id == "CWE-89"


def test_labeled_queries_cover_seed_units() -> None:
    queries = load_retrieval_queries()
    assert len(queries) == 18
    unit_queries = [item for item in queries if item.unit_id]
    assert len(unit_queries) == 12


def test_hybrid_retriever_returns_hits() -> None:
    retriever = HybridRetriever.load()
    query = RetrievalQuery(
        query_id="t",
        query="SQL query built with string concatenation into Statement.executeQuery.",
        relevant_cwes=("CWE-89",),
        unit_id="java_cwe89_sqli_concat",
    )
    hybrid = retriever.hybrid_rank(query)
    assert hybrid
    assert any(hit.cwe_id == "CWE-89" for hit in hybrid[:3])
    sast = retriever.sast_rank(query)
    assert any(hit.cwe_id == "CWE-89" for hit in sast)
