"""OpenAI-compatible LLM reasoner behind the same Reasoner port as TemplateReasoner.

Pipeline.default() requires a Groq key. Import is always safe; from_env() returns None
without a key so tests and --offline can skip construction.

Failure policy (thesis evaluation integrity):
- Rate-limit / quota errors are RE-RAISED, never converted to a template answer;
  the trial runner backs off and marks the suite rate_limited.
- Invalid JSON / schema failures retry once, then fall back to TemplateReasoner
  with ``fallback_reason`` recorded (never silent).
- Token usage, latency, attempts, and the raw response are exposed after each
  call so trials can log them per unit.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any

from cwe_vuln.config import settings
from cwe_vuln.dataset import SeedUnit
from cwe_vuln.knowledge import CWEKnowledgeBase
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.reasoning import ReasoningResult
from cwe_vuln.models.retrieval import RankedHit
from cwe_vuln.reasoner.prompts import SYSTEM_PROMPT, RenderedPrompt, render_prompt
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
        # Per-unit diagnostics, reset at the start of every reason() call.
        self.last_backend = "llm"
        self.last_errors: list[str] = []
        self.fallback_reason: str | None = None
        self.n_attempts = 0
        self.last_usage: dict[str, int] | None = None
        self.last_latency_ms: int | None = None
        self.last_raw: str = ""
        self.last_prompt: RenderedPrompt | None = None
        self.last_finish_reason: str | None = None

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
        self.last_prompt = render_prompt(unit, evidence, hits)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": self.last_prompt.text},
        ]
        self.last_errors = []
        self.fallback_reason = None
        self.n_attempts = 0
        self.last_raw = ""
        last_text = ""
        for _attempt in range(2):
            self.n_attempts += 1
            try:
                last_text = self._complete(messages)
                self.last_raw = last_text
                payload = parse_json_object(last_text)
                payload = self._normalize(payload, unit, evidence)
                if is_valid(payload):
                    self.last_backend = "llm"
                    return ReasoningResult.from_dict(payload)
                self.last_errors = validate_output(payload) or ["schema failed"]
            except Exception as exc:
                if _is_rate_limit_error(exc):
                    logger.warning("Groq rate limit hit; surfacing to trial runner: %s", exc)
                    raise
                self.last_errors = [f"{type(exc).__name__}: {exc}"]
            messages.append({"role": "assistant", "content": last_text or ""})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Your previous output was not valid Assignment 4 JSON "
                        f"({self.last_errors}). Return only the JSON object, no markdown."
                    ),
                }
            )
        self.fallback_reason = "; ".join(self.last_errors)[:300] or "unknown"
        logger.info("LLM JSON invalid after retry; reasoner=llm_fallback_template (%s)", self.fallback_reason)
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
        """Fill mechanical fields only. The model's cited lines are kept as-is:
        substituting evidence spans here would make cited_lines a hidden pass."""
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
        span = payload.get("supporting_source_lines")
        if isinstance(span, dict):
            # Path echo is not a quality signal (we hand it to the model); the
            # line numbers and snippet stay exactly what the model wrote.
            span["path"] = unit.path
            payload["supporting_source_lines"] = span
        if evidence and "evidence_ids" not in payload:
            payload["evidence_ids"] = [item.evidence_id for item in evidence]
        return payload

    def _chat_complete(self, messages: list[dict[str, str]]) -> str:
        from openai import OpenAI

        kwargs: dict[str, Any] = {"api_key": self.api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        client = OpenAI(**kwargs)
        started = time.monotonic()
        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0,
            response_format={"type": "json_object"},
        )
        self.last_latency_ms = int((time.monotonic() - started) * 1000)
        usage = getattr(response, "usage", None)
        if usage is not None:
            self.last_usage = {
                "prompt_tokens": int(getattr(usage, "prompt_tokens", 0) or 0),
                "completion_tokens": int(getattr(usage, "completion_tokens", 0) or 0),
            }
        choice = response.choices[0]
        self.last_finish_reason = getattr(choice, "finish_reason", None)
        content = choice.message.content
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


def _is_rate_limit_error(exc: Exception) -> bool:
    """True for Groq/OpenAI 429s and quota errors, including mocked clients."""
    status = getattr(exc, "status_code", None) or getattr(exc, "http_status", None)
    if status == 429:
        return True
    name = type(exc).__name__.lower()
    if "ratelimit" in name or "rate_limit" in name:
        return True
    text = str(exc).lower()
    return "429" in text or "rate limit" in text or "tokens per day" in text


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
