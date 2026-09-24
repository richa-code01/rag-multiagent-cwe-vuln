"""Hybrid CWE retrieval: neural or TF-IDF, SAST ids, relationship expansion, RRF fuse."""

from cwe_vuln.models.retrieval import RankedHit, RetrievalQuery
from cwe_vuln.retrieval.dense import DenseIndex, cosine_rank
from cwe_vuln.retrieval.embed import Embedder, MiniLMEmbedder, TfidfEmbedder, load_embedder
from cwe_vuln.retrieval.hybrid import HybridRetriever, evaluate_retriever, load_retrieval_queries
from cwe_vuln.retrieval.index import TfidfIndex, tokenize
from cwe_vuln.retrieval.rank import mean, mean_reciprocal_rank, recall_at_k, rrf_combine

__all__ = [
    "DenseIndex",
    "Embedder",
    "HybridRetriever",
    "MiniLMEmbedder",
    "RankedHit",
    "RetrievalQuery",
    "TfidfEmbedder",
    "TfidfIndex",
    "cosine_rank",
    "evaluate_retriever",
    "load_embedder",
    "load_retrieval_queries",
    "mean",
    "mean_reciprocal_rank",
    "recall_at_k",
    "rrf_combine",
    "tokenize",
]
