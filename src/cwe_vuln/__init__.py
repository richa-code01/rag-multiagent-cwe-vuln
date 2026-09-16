"""Java CWE seed, SAST-style baseline, and curated CWE knowledge queries."""

from cwe_vuln.dataset import SeedUnit, load_seed
from cwe_vuln.detector import Detection, detect
from cwe_vuln.knowledge import CWEEntry, CWEKnowledgeBase
from cwe_vuln.metrics import BinaryMetrics, binary_metrics

__version__ = "0.2.0"

__all__ = [
    "BinaryMetrics",
    "CWEEntry",
    "CWEKnowledgeBase",
    "Detection",
    "SeedUnit",
    "binary_metrics",
    "detect",
    "load_seed",
    "__version__",
]
