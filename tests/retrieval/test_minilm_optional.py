import pytest

from cwe_vuln.retrieval.embed import MiniLMEmbedder, minilm_cache_ready


@pytest.mark.skipif(not minilm_cache_ready(), reason="MiniLM model not cached")
def test_minilm_encode_two_texts_same_dim() -> None:
    embedder = MiniLMEmbedder.try_load(allow_download=False)
    assert embedder is not None
    vecs = embedder.encode(["sql injection", "cross site scripting"])
    assert len(vecs) == 2
    assert len(vecs[0]) == len(vecs[1])
    assert len(vecs[0]) > 8
