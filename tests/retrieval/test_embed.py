from cwe_vuln.retrieval import DenseIndex, TfidfEmbedder, TfidfIndex, cosine_rank
from cwe_vuln.retrieval.embed import MiniLMEmbedder, minilm_cache_ready


class KeywordEmbedder:
    """Tiny fake embedder for unit tests. No MiniLM and no network."""

    name = "fake_keyword"
    axes = ("sql", "injection", "xss", "html", "path", "serial", "password", "digest")

    def encode(self, texts):
        rows = []
        for text in texts:
            low = text.lower()
            rows.append([float(low.count(axis)) for axis in self.axes])
        return rows


def test_cosine_ranker_with_fake_embedder() -> None:
    docs = {
        "CWE-89": "sql injection concatenated query statement",
        "CWE-79": "html xss cross site scripting encode",
    }
    embedder = KeywordEmbedder()
    index = DenseIndex(docs, embedder)
    hits = index.rank("sql injection query")
    assert hits[0].cwe_id == "CWE-89"


def test_cosine_rank_helper_orders_by_similarity() -> None:
    hits = cosine_rank([1.0, 0.0], ["a", "b"], [[1.0, 0.0], [0.0, 1.0]])
    assert [hit.cwe_id for hit in hits] == ["a", "b"]
    assert hits[0].score > hits[1].score


def test_tfidf_embedder_matches_lexical_winner() -> None:
    documents = {
        "CWE-89": "sql injection concatenated query statement",
        "CWE-79": "html cross site scripting output encode",
    }
    embedder = TfidfEmbedder(documents=documents)
    index = DenseIndex(documents, embedder)
    hits = index.rank("sql injection query")
    lexical = TfidfIndex(documents).rank("sql injection query")
    assert hits[0].cwe_id == lexical[0].cwe_id == "CWE-89"


def test_minilm_try_load_without_cache_does_not_raise() -> None:
    if minilm_cache_ready():
        embedder = MiniLMEmbedder.try_load(allow_download=False)
        assert embedder is None or embedder.name == "minilm"
        return
    assert MiniLMEmbedder.try_load(allow_download=False) is None
