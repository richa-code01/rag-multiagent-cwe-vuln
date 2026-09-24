"""Retrieval must query sanitized source, never gold-bearing unit.notes, and return passages."""

from cwe_vuln.dataset import load_seed
from cwe_vuln.dataset.sanitize import sanitize_unit
from cwe_vuln.models.retrieval import RetrievalQuery
from cwe_vuln.retrieval import HybridRetriever


def test_rank_for_unit_does_not_use_notes() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    poisoned = unit.__class__(
        unit_id=unit.unit_id,
        cwe_id=unit.cwe_id,
        path=unit.path,
        split=unit.split,
        label=unit.label,
        notes="real=true cwe=89 POTENTIAL FLAW method_bad",
        source=unit.source,
        trap_type=unit.trap_type,
        corpus=unit.corpus,
    )
    retriever = HybridRetriever.load()
    hits = retriever.rank_for_unit(poisoned)
    assert hits
    assert any(hit.cwe_id == "CWE-89" for hit in hits[:5])
    assert any(hit.passage for hit in hits)


def test_sanitized_source_query_still_ranks_cwe89() -> None:
    unit = next(item for item in load_seed() if item.unit_id == "java_cwe89_sqli_concat")
    clean = sanitize_unit(unit)
    retriever = HybridRetriever.load()
    query = RetrievalQuery(
        query_id=clean.unit_id,
        query=clean.source[:1500],
        relevant_cwes=("CWE-89",),
        unit_id=clean.unit_id,
    )
    ranked = [hit.cwe_id for hit in retriever.hybrid_rank(query)]
    assert "CWE-89" in ranked[:5]


def test_retrieval_query_is_sink_window_not_file_head() -> None:
    from cwe_vuln.dataset.sanitize import retrieval_query_text
    from cwe_vuln.dataset.seed import SeedUnit

    pad = ["int filler%04d = 0;" % n for n in range(400)]
    sink = '        stmt.executeQuery("SELECT * FROM t WHERE x=" + value);'
    source = "\n".join(["package x;", "class Big {"] + pad + [sink, "}"])
    unit = SeedUnit(
        unit_id="big_sink",
        cwe_id="CWE-89",
        path="Big.java",
        split="juliet",
        label="vulnerable",
        notes="",
        source=source,
    )
    query = retrieval_query_text(unit)
    assert "executeQuery" in query
    assert "filler0000" not in query
    retriever = HybridRetriever.load()
    hits = retriever.rank_for_unit(sanitize_unit(unit))
    assert hits
