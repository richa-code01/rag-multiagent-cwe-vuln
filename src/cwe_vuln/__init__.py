"""Assignment 1 package: Java CWE seed loading and a SAST-style baseline detector."""

from cwe_vuln.dataset import SeedUnit, load_seed
from cwe_vuln.detector import Detection, detect
from cwe_vuln.metrics import BinaryMetrics, binary_metrics

__version__ = "0.1.0"

__all__ = [
    "BinaryMetrics",
    "Detection",
    "SeedUnit",
    "binary_metrics",
    "detect",
    "load_seed",
    "__version__",
]
