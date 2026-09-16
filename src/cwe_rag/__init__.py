"""Public package surface for the seed research slice."""

from cwe_rag.evaluate import SeedMetrics, evaluate_seed
from cwe_rag.pipeline import detect

__all__ = ["detect", "evaluate_seed", "SeedMetrics"]
