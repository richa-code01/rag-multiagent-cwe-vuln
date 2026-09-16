"""Java CWE seed, SAST baseline, CWE knowledge, hybrid retrieval, and output schema."""

from cwe_vuln.dataset import SeedUnit, load_seed
from cwe_vuln.detector import Detection, detect
from cwe_vuln.evidence import Evidence, extract_evidence
from cwe_vuln.knowledge import CWEEntry, CWEKnowledgeBase
from cwe_vuln.metrics import BinaryMetrics, binary_metrics
from cwe_vuln.retrieval import HybridRetriever, RankedHit
from cwe_vuln.schema import ReasoningResult, is_valid, validate_output

__version__ = "0.4.0"

__all__ = [
    "BinaryMetrics",
    "CWEEntry",
    "CWEKnowledgeBase",
    "Detection",
    "Evidence",
    "HybridRetriever",
    "RankedHit",
    "ReasoningResult",
    "SeedUnit",
    "binary_metrics",
    "detect",
    "extract_evidence",
    "is_valid",
    "load_seed",
    "validate_output",
    "__version__",
]
