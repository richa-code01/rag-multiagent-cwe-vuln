"""Java CWE seed, SAST-style baseline, CWE knowledge, and hybrid retrieval."""

from cwe_vuln.dataset import SeedUnit, load_seed
from cwe_vuln.detector import Detection, detect
from cwe_vuln.knowledge import CWEEntry, CWEKnowledgeBase
from cwe_vuln.metrics import BinaryMetrics, binary_metrics
from cwe_vuln.retrieval import HybridRetriever, RankedHit

__version__ = "0.3.0"

__all__ = [
    "BinaryMetrics",
    "CWEEntry",
    "CWEKnowledgeBase",
    "Detection",
    "HybridRetriever",
    "RankedHit",
    "SeedUnit",
    "binary_metrics",
    "detect",
    "load_seed",
    "__version__",
]
