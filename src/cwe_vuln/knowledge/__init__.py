"""CWE store and query interface. Descriptions and mitigations live here, not in SAST rules."""

from cwe_vuln.config import SEED_CWE_IDS
from cwe_vuln.knowledge.store import (
    CWEEntry,
    CWEKnowledgeBase,
    KnowledgeError,
    Mitigation,
    Relationships,
    default_knowledge_path,
    normalize_cwe_id,
)

__all__ = [
    "CWEEntry",
    "CWEKnowledgeBase",
    "KnowledgeError",
    "Mitigation",
    "Relationships",
    "SEED_CWE_IDS",
    "default_knowledge_path",
    "normalize_cwe_id",
]
