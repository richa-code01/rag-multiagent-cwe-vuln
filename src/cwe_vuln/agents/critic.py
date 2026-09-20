"""CriticAgent: optional second-LLM reviewer (ablation only, never the default).

The default thesis validator is deterministic (reproducible, free). This agent
exists to measure whether an LLM verifier would change decisions — the same
question HeterogenousMAS's LLM verifier raises. It reviews the ReasoningAgent's
JSON against the sanitized unit and returns ACCEPT / CHALLENGE / REJECT with a
one-line rationale. Used only via `--ablation critic`.
"""

from __future__ import annotations

import json
import logging

from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.reasoning import ReasoningResult
from cwe_vuln.reasoner.llm import LLMReasoner, parse_json_object
from cwe_vuln.reasoner.prompts import render_prompt

logger = logging.getLogger(__name__)

CRITIC_SYSTEM = """You are a strict security review critic.
You are given a Java unit and a vulnerability analysis JSON produced by another model.
Return ONLY JSON: {"verdict": "ACCEPT" | "CHALLENGE" | "REJECT", "rationale": one sentence}.
ACCEPT: decision, CWE, and cited lines are consistent with the code.
CHALLENGE: plausible but a specific detail is wrong (say which).
REJECT: decision contradicts the code. Do not generate exploits."""


class CriticAgent:
    name = "critic"

    def __init__(self, llm: LLMReasoner) -> None:
        self.llm = llm
        self.last_verdict: str | None = None
        self.last_rationale: str | None = None

    def review(self, unit: SeedUnit, result: ReasoningResult) -> dict[str, str]:
        """Review one reasoning result. Rate limits propagate (trial runner handles)."""
        prompt = render_prompt(unit, [], [])
        analysis = json.dumps(result.to_dict(), indent=2)
        messages = [
            {"role": "system", "content": CRITIC_SYSTEM},
            {
                "role": "user",
                "content": f"Java unit:\n{prompt.text}\n\nAnalysis under review:\n{analysis}",
            },
        ]
        self.last_verdict = None
        self.last_rationale = None
        try:
            text = self.llm._complete(messages)
            payload = parse_json_object(text)
            verdict = str(payload.get("verdict", "")).upper()
            if verdict not in {"ACCEPT", "CHALLENGE", "REJECT"}:
                verdict = "CHALLENGE"
            self.last_verdict = verdict
            self.last_rationale = str(payload.get("rationale", ""))[:300]
        except Exception as exc:
            # Rate limits must surface; everything else is a recorded critic failure.
            from cwe_vuln.reasoner.llm import _is_rate_limit_error

            if _is_rate_limit_error(exc):
                raise
            logger.info("critic failed: %s", exc)
            self.last_verdict = "ERROR"
            self.last_rationale = f"{type(exc).__name__}: {exc}"[:300]
        return {"verdict": self.last_verdict, "rationale": self.last_rationale or ""}
