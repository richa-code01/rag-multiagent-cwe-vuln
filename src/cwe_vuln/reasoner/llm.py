"""LLM reasoner behind the same Reasoner port as TemplateReasoner.

Talks to a `ChatProvider` (Groq, OpenAI, Together, Ollama, custom, …). The
vendor SDK lives in `cwe_vuln.llm`; this module only retries JSON and records
diagnostics. Pipeline.default() requires a configured provider. Import is always
safe; from_env() returns None without a key so tests and --offline can skip.

Failure policy (thesis evaluation integrity):
- Rate-limit / quota errors are RE-RAISED, never converted to a template answer.
- Invalid JSON / schema failures retry once, then fall back to TemplateReasoner
  with ``fallback_reason`` recorded (never silent).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from cwe_vuln.config import settings
from cwe_vuln.dataset import SeedUnit
from cwe_vuln.knowledge import CWEKnowledgeBase
from cwe_vuln.llm import ChatProvider, ChatResult, OpenAICompatProvider, RateLimitError
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
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        complete: CompleteFn | None = None,
        fallback: TemplateReasoner | None = None,
        kb: CWEKnowledgeBase | None = None,
        provider: ChatProvider | None = None,
    ) -> None:
        self.provider = provider
        if self.provider is None and complete is None:
            if not api_key:
                raise ValueError("LLMReasoner requires a ChatProvider, api_key, or complete= stub")
            built = OpenAICompatProvider.from_env(api_key=api_key, model=model, base_url=base_url)
            if built is None:
                raise ValueError("LLMReasoner could not build a provider from env")
            self.provider = built
        self.api_key = getattr(self.provider, "api_key", None) or api_key or ""
        self.model = getattr(self.provider, "model", None) or model or settings.llm_model()
        self.base_url = (
            getattr(self.provider, "base_url", None)
            if getattr(self.provider, "base_url", None)
            else (base_url if base_url is not None else settings.llm_base_url())
        )
        self.provider_name = getattr(self.provider, "name", None) or settings.llm_provider()
        self._complete = complete or self._provider_complete
        self.kb = kb or CWEKnowledgeBase.load()
        self.fallback = fallback or TemplateReasoner(kb=self.kb)
        self.last_backend = "llm"
        self.last_errors: list[str] = []
        self.fallback_reason: str | None = None
        self.n_attempts = 0
        self.last_usage: dict[str, int] | None = None
        self.last_latency_ms: int | None = None
        self.last_raw: str = ""
        self.last_prompt: RenderedPrompt | None = None
        self.last_finish_reason: str | None = None
        self.last_cwe_clamped_from: str | None = None

    @classmethod
    def from_env(cls) -> LLMReasoner | None:
        provider = OpenAICompatProvider.from_env()
        if provider is None:
            return None
        return cls(provider=provider)

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
        self.last_cwe_clamped_from = None
        last_text = ""
        for _attempt in range(2):
            self.n_attempts += 1
            try:
                last_text = self._complete(messages)
                self.last_raw = last_text
                payload = parse_json_object(last_text)
                payload = self._normalize(payload, unit, evidence, hits)
                if is_valid(payload):
                    self.last_backend = "llm"
                    return ReasoningResult.from_dict(payload)
                self.last_errors = validate_output(payload) or ["schema failed"]
            except Exception as exc:
                if _is_rate_limit_error(exc):
                    logger.warning("LLM rate limit hit; surfacing to trial runner: %s", exc)
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
        self.last_cwe_clamped_from = None
        return self.fallback.reason(unit, evidence, hits)

    def compose(
        self,
        unit: SeedUnit,
        evidence: list[Evidence],
        hits: list[RankedHit],
    ) -> ReasoningResult:
        return self.reason(unit, evidence, hits)

    def _normalize(
        self,
        payload: dict[str, Any],
        unit: SeedUnit,
        evidence: list[Evidence],
        hits: list[RankedHit] | None = None,
    ) -> dict[str, Any]:
        """Fill mechanical fields only. The model's cited lines are kept as-is.

        Unknown CWE ids (including CWE-0) are clamped to the top retrieved/evidence
        id that exists in the KB. The original id is recorded on
        ``last_cwe_clamped_from``.
        """
        payload = {key: value for key, value in payload.items() if key in _ALLOWED_FIELDS}
        payload["unit_id"] = unit.unit_id
        payload["schema_version"] = payload.get("schema_version") or "1.0"
        allowed = _allowed_cwe_ids(self.kb, evidence, hits or [])
        cwe = payload.get("cwe")
        self.last_cwe_clamped_from = None
        if isinstance(cwe, dict):
            cwe = {key: value for key, value in cwe.items() if key in {"id", "name"}}
            raw_id = str(cwe.get("id") or "")
            clamped_id, clamped_from = _clamp_cwe_id(raw_id, allowed, self.kb)
            if clamped_from is not None:
                self.last_cwe_clamped_from = clamped_from
            cwe["id"] = clamped_id
            entry = self.kb.entries.get(clamped_id)
            if entry is not None:
                cwe["name"] = entry.name
            payload["cwe"] = cwe
        span = payload.get("supporting_source_lines")
        if isinstance(span, dict):
            span["path"] = unit.path
            payload["supporting_source_lines"] = span
        if evidence and "evidence_ids" not in payload:
            payload["evidence_ids"] = [item.evidence_id for item in evidence]
        return payload

    def _provider_complete(self, messages: list[dict[str, str]]) -> str:
        if self.provider is None:
            raise RuntimeError("LLMReasoner has no ChatProvider")
        result = self.provider.complete(messages)
        self._record_result(result)
        return result.text

    def _record_result(self, result: ChatResult) -> None:
        self.last_latency_ms = result.latency_ms
        self.last_finish_reason = result.finish_reason
        if result.prompt_tokens is not None or result.completion_tokens is not None:
            self.last_usage = {
                "prompt_tokens": int(result.prompt_tokens or 0),
                "completion_tokens": int(result.completion_tokens or 0),
            }
        if result.model:
            self.model = result.model
        if result.provider:
            self.provider_name = result.provider


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


def _allowed_cwe_ids(kb: CWEKnowledgeBase, evidence: list[Evidence], hits: list[RankedHit]) -> list[str]:
    ids: list[str] = []
    for hit in hits:
        if hit.cwe_id in kb.entries:
            ids.append(hit.cwe_id)
    for item in evidence:
        cwe_id = getattr(item, "cwe_id", "")
        if cwe_id in kb.entries:
            ids.append(cwe_id)
    return list(dict.fromkeys(ids))


def _clamp_cwe_id(
    raw_id: str,
    allowed: list[str],
    kb: CWEKnowledgeBase,
) -> tuple[str, str | None]:
    """Map unknown / CWE-0 ids onto the first allowed KB id. Identity otherwise."""
    if raw_id in kb.entries and raw_id != "CWE-0":
        return raw_id, None
    if allowed:
        return allowed[0], raw_id or "CWE-0"
    return raw_id, None


def _is_rate_limit_error(exc: Exception) -> bool:
    """True for 429/quota errors, including mocked clients and RateLimitError."""
    if isinstance(exc, RateLimitError):
        return True
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
