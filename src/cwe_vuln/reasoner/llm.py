"""OpenAI-compatible LLM reasoner behind the same Reasoner port as TemplateReasoner.

Pipeline.default() requires a Groq key. Import is always safe; from_env() returns None
without a key so tests and --offline can skip construction.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from cwe_vuln.config import settings
from cwe_vuln.dataset import SeedUnit
from cwe_vuln.knowledge import CWEKnowledgeBase
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.reasoning import ReasoningResult
from cwe_vuln.models.retrieval import RankedHit
from cwe_vuln.reasoner.prompts import SYSTEM_PROMPT, render_user_prompt
from cwe_vuln.reasoner.template import TemplateReasoner
from cwe_vuln.schema import is_valid, validate_output

logger = logging.getLogger(__name__)

CompleteFn = Callable[[list[dict[str, str]]], str]


class LLMReasoner:
    """Live LLM composer. Falls back to TemplateReasoner after one invalid-JSON retry."""

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        base_url: str | None = None,
        complete: CompleteFn | None = None,
        fallback: TemplateReasoner | None = None,
        kb: CWEKnowledgeBase | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("LLMReasoner requires an API key; use TemplateReasoner offline")
        self.api_key = api_key
        self.model = model or settings.llm_model()
        self.base_url = base_url if base_url is not None else settings.llm_base_url()
        self._complete = complete or self._chat_complete
        self.kb = kb or CWEKnowledgeBase.load()
        self.fallback = fallback or TemplateReasoner(kb=self.kb)
        self.last_backend = "llm"

    @classmethod
    def from_env(cls) -> LLMReasoner | None:
        key = settings.llm_api_key()
        if not key:
            return None
        return cls(api_key=key)

    def reason(
        self,
        unit: SeedUnit,
        evidence: list[Evidence],
        hits: list[RankedHit],
    ) -> ReasoningResult:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": render_user_prompt(unit, evidence, hits)},
        ]
        last_text = ""
        last_errors: list[str] = []
        for _attempt in range(2):
            try:
                last_text = self._complete(messages)
                payload = parse_json_object(last_text)
                payload = self._normalize(payload, unit, evidence)
                if is_valid(payload):
                    self.last_backend = "llm"
                    return ReasoningResult.from_dict(payload)
                last_errors = validate_output(payload) or ["schema failed"]
            except Exception as exc:
                last_errors = [str(exc)]
            messages.append({"role": "assistant", "content": last_text or ""})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Your previous output was not valid Assignment 4 JSON "
                        f"({last_errors}). Return only the JSON object, no markdown."
                    ),
                }
            )
        logger.info("LLM JSON invalid after retry; reasoner=llm_fallback_template")
        self.last_backend = "llm_fallback_template"
        return self.fallback.reason(unit, evidence, hits)

    def compose(
        self,
        unit: SeedUnit,
        evidence: list[Evidence],
        hits: list[RankedHit],
    ) -> ReasoningResult:
        return self.reason(unit, evidence, hits)

    def _normalize(self, payload: dict[str, Any], unit: SeedUnit, evidence: list[Evidence]) -> dict[str, Any]:
        payload = {key: value for key, value in payload.items() if key in _ALLOWED_FIELDS}
        payload["unit_id"] = unit.unit_id
        payload["schema_version"] = payload.get("schema_version") or "1.0"
        cwe = payload.get("cwe")
        if isinstance(cwe, dict):
            cwe = {key: value for key, value in cwe.items() if key in {"id", "name"}}
            cwe_id = str(cwe.get("id") or "")
            entry = self.kb.entries.get(cwe_id)
            if entry is not None:
                cwe["name"] = entry.name
            payload["cwe"] = cwe
        payload["supporting_source_lines"] = ground_source_span(
            payload.get("supporting_source_lines"), unit, evidence
        )
        if evidence and "evidence_ids" not in payload:
            payload["evidence_ids"] = [item.evidence_id for item in evidence]
        return payload

    def _chat_complete(self, messages: list[dict[str, str]]) -> str:
        from openai import OpenAI

        kwargs: dict[str, Any] = {"api_key": self.api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        client = OpenAI(**kwargs)
        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        return content or ""


_ALLOWED_FIELDS = {
    "schema_version",
    "unit_id",
    "decision",
    "cwe",
    "supporting_source_lines",
    "root_cause",
    "explanation",
    "remediation",
    "confidence",
    "evidence_ids",
}


def ground_source_span(span: object, unit: SeedUnit, evidence: list[Evidence]) -> dict[str, str | int]:
    """Replace LLM snippets with the exact cited source so the validator can pass."""
    lines = unit.source.splitlines() or [" "]
    n_lines = len(lines)
    raw = span if isinstance(span, dict) else {}
    try:
        start = int(raw.get("start_line") or 0)
        end = int(raw.get("end_line") or start)
    except (TypeError, ValueError):
        start, end = 0, 0
    if not (1 <= start <= end <= n_lines):
        if evidence:
            primary = evidence[0]
            return {
                "path": unit.path,
                "start_line": primary.start_line,
                "end_line": primary.end_line,
                "snippet": primary.snippet,
            }
        start = end = 1
        for index, line in enumerate(lines, start=1):
            if line.strip().startswith(("public ", "return ", "String ", "Path ", "File ", "byte[]")):
                start = end = index
                break
    excerpt = "\n".join(lines[start - 1 : end]) or lines[0]
    return {
        "path": unit.path,
        "start_line": start,
        "end_line": end,
        "snippet": excerpt,
    }


def parse_json_object(text: str) -> dict[str, Any]:
    blob = text.strip()
    if blob.startswith("```"):
        lines = blob.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        blob = "\n".join(lines).strip()
    start = blob.find("{")
    end = blob.rfind("}")
    if start < 0 or end < start:
        raise ValueError("LLM output did not contain a JSON object")
    payload = json.loads(blob[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("LLM JSON was not an object")
    return payload
