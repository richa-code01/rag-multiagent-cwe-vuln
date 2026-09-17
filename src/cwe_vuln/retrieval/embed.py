"""Embedder port: MiniLM neural encoder with TF-IDF fallback. Never raises at import."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Protocol, Sequence

from cwe_vuln.config import minilm_cache_dir, settings
from cwe_vuln.retrieval.index import TfidfIndex

logger = logging.getLogger(__name__)

Matrix = Sequence[Sequence[float]]


class Embedder(Protocol):
    name: str

    def encode(self, texts: Sequence[str]) -> Matrix:
        """Return a 2-D array-like of shape (n_texts, dim)."""


def default_allow_download() -> bool:
    if os.environ.get("CWE_VULN_SKIP_MINILM") == "1":
        return False
    if os.environ.get("CWE_VULN_DOWNLOAD_MINILM") == "1":
        return True
    return os.environ.get("PYTEST_CURRENT_TEST") is None


def minilm_cache_ready(cache: Path | None = None) -> bool:
    root = cache or minilm_cache_dir()
    if not root.exists():
        return False
    return any(root.rglob("config.json"))


class MiniLMEmbedder:
    """Local sentence-transformers encoder. Construction must not run at import time."""

    name = "minilm"

    def __init__(self, model: object) -> None:
        self._model = model

    @classmethod
    def try_load(cls, allow_download: bool | None = None) -> MiniLMEmbedder | None:
        if not settings.use_neural_if_available:
            return None
        allow = default_allow_download() if allow_download is None else allow_download
        if not allow and not minilm_cache_ready():
            return None
        try:
            from sentence_transformers import SentenceTransformer
        except Exception as exc:
            logger.info("MiniLM import failed (%s); embedder=tfidf_fallback", exc)
            return None
        cache = minilm_cache_dir()
        cache.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("SENTENCE_TRANSFORMERS_HOME", str(cache))
        os.environ.setdefault("HF_HOME", str(cache.parent / "huggingface"))
        kwargs: dict[str, object] = {"cache_folder": str(cache)}
        if not allow or minilm_cache_ready(cache):
            kwargs["local_files_only"] = True
        try:
            model = SentenceTransformer(settings.minilm_model, **kwargs)
        except TypeError:
            if not allow and not minilm_cache_ready(cache):
                return None
            try:
                model = SentenceTransformer(settings.minilm_model, cache_folder=str(cache))
            except Exception as exc:
                logger.info("MiniLM load failed (%s); embedder=tfidf_fallback", exc)
                return None
        except Exception as exc:
            logger.info("MiniLM load failed (%s); embedder=tfidf_fallback", exc)
            return None
        return cls(model)

    def encode(self, texts: Sequence[str]) -> Matrix:
        vecs = self._model.encode(list(texts), convert_to_numpy=True, show_progress_bar=False)
        return _as_matrix(vecs)


class TfidfEmbedder:
    """Lexical TF-IDF vectors aligned to a fitted vocabulary. Offline, no model download."""

    name = "tfidf"

    def __init__(self, documents: dict[str, str] | None = None, index: TfidfIndex | None = None) -> None:
        if index is None:
            if documents is None:
                raise ValueError("TfidfEmbedder needs documents or a fitted TfidfIndex")
            index = TfidfIndex(documents)
        self.index = index
        self.vocab = tuple(sorted(index.idf))

    def encode(self, texts: Sequence[str]) -> Matrix:
        dim = self.vocab
        rows: list[list[float]] = []
        for text in texts:
            vec = self.index.vectorize(text)
            rows.append([vec.get(token, 0.0) for token in dim] if dim else [0.0])
        return rows


def load_embedder(
    documents: dict[str, str],
    allow_download: bool | None = None,
) -> tuple[Embedder, str]:
    """Return (embedder, status). status is `minilm` or `tfidf_fallback`."""
    neural = MiniLMEmbedder.try_load(allow_download=allow_download)
    if neural is not None:
        return neural, "minilm"
    return TfidfEmbedder(documents=documents), "tfidf_fallback"


def _as_matrix(vecs: object) -> list[list[float]]:
    if hasattr(vecs, "tolist"):
        data = vecs.tolist()
    else:
        data = list(vecs)  # type: ignore[arg-type]
    if not data:
        return []
    first = data[0]
    if isinstance(first, (int, float)):
        return [[float(x) for x in data]]
    return [[float(x) for x in row] for row in data]
