"""Named agents over the pipeline ports (ApproachDoc stages 1-6).

The thesis system is a multi-agent pipeline in the tool-augmented sense:
specialized agents with distinct roles communicate through structured messages
(Evidence, RankedHit, ReasoningResult, ValidationReport) under a deterministic
orchestrator — not free-form LLM conversations. The agents are thin, honest
wrappers: each owns one responsibility and exposes it through the existing port
protocols, so the orchestrator can wire agents or test doubles interchangeably.
"""

from cwe_vuln.agents.evidence import EvidenceAgent
from cwe_vuln.agents.knowledge import KnowledgeAgent
from cwe_vuln.agents.reasoning import ReasoningAgent
from cwe_vuln.agents.validation import ValidatorAgent

__all__ = [
    "EvidenceAgent",
    "KnowledgeAgent",
    "ReasoningAgent",
    "ValidatorAgent",
]
