"""Assignment 4 JSON-only prompts. Detection and explanation; no exploit generation."""

from __future__ import annotations

import json

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.retrieval import RankedHit

SYSTEM_PROMPT = """You are a software vulnerability analyst for a pedagogical Java seed.
Return ONLY a JSON object that matches the Assignment 4 reasoning schema.
Do not generate exploits, payloads, or attack instructions.
Decide vulnerable / not_vulnerable / uncertain from the given SAST evidence and code excerpt.
Ground the CWE id in the retrieval hits when possible. Keep explanation and remediation defensive."""

USER_PROMPT = """Analyze this Java seed unit. Return JSON only, no markdown.

Required keys:
  schema_version: "1.0"
  unit_id: string (use the unit_id below)
  decision: "vulnerable" | "not_vulnerable" | "uncertain"
  cwe: {{"id": "CWE-NNN", "name": "..."}}
  supporting_source_lines: {{"path": "...", "start_line": int, "end_line": int, "snippet": "..."}}
  (snippet must be copied verbatim from those source lines, including indentation)
  root_cause: string
  explanation: string
  remediation: string
Optional keys: confidence (0-1), evidence_ids (array of strings).

unit_id: {unit_id}
path: {path}

Code excerpt:
{source}

SAST evidence JSON:
{evidence}

Top-K CWE retrieval hits JSON:
{hits}
"""


def render_user_prompt(unit: SeedUnit, evidence: list[Evidence], hits: list[RankedHit], max_chars: int = 4000) -> str:
    source = unit.source if len(unit.source) <= max_chars else unit.source[:max_chars] + "\n...[truncated]..."
    evidence_payload = [item.to_dict() for item in evidence]
    hits_payload = [{"cwe_id": hit.cwe_id, "score": hit.score, "name": hit.name} for hit in hits]
    return USER_PROMPT.format(
        unit_id=unit.unit_id,
        path=unit.path,
        source=source,
        evidence=json.dumps(evidence_payload, indent=2),
        hits=json.dumps(hits_payload, indent=2),
    )
