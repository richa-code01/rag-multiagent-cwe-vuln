"""Assignment 4 JSON-only prompts. Detection and explanation; no exploit generation.

The source excerpt is rendered with absolute line-number prefixes (``  42| code``)
so the LLM can cite lines without counting. When a unit exceeds the character
budget, a window around the SAST evidence (or a sink heuristic) is shown instead
of the file head; prefixes stay absolute, so cited lines still validate against
the full sanitized source.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from cwe_vuln.config import settings
from cwe_vuln.dataset import SeedUnit
from cwe_vuln.models.evidence import Evidence
from cwe_vuln.models.retrieval import RankedHit

SYSTEM_PROMPT = """You are a senior Java application-security analyst.
Return ONLY a JSON object that matches the Assignment 4 reasoning schema.
Do not generate exploits, payloads, or attack instructions.
Decide vulnerable / not_vulnerable / uncertain from the given SAST evidence, the code excerpt, and the retrieved CWE knowledge.
The CWE id MUST be one of the allowed retrieval-hit ids listed in the user prompt. Never emit CWE-0 or an id outside that list. If uncertain, still pick the nearest allowed hit id.
Keep explanation and remediation defensive."""

USER_PROMPT = """Analyze this Java unit. Return JSON only, no markdown.

Required keys:
  schema_version: "1.0"
  unit_id: string (use the unit_id below)
  decision: "vulnerable" | "not_vulnerable" | "uncertain"
  cwe: {{"id": "CWE-NNN", "name": "..."}}
  supporting_source_lines: {{"path": "...", "start_line": int, "end_line": int, "snippet": "..."}}
  (start_line/end_line must use the absolute line numbers shown in the excerpt;
   snippet must be the cited code copied verbatim WITHOUT the line-number prefixes)
  root_cause: string
  explanation: string
  remediation: string
Optional keys: confidence (0-1), evidence_ids (array of strings).

unit_id: {unit_id}
path: {path}

Allowed CWE ids (pick exactly one; never CWE-0 or an id outside this list):
{allowed_cwe_ids}

Code excerpt ({window_note}):
{source}

SAST evidence JSON:
{evidence}

Top-K CWE retrieval hits JSON:
{hits}
"""

# Sinks used to center the prompt window when regex evidence is empty.
_SINK_HINT = re.compile(
    r"getParameter|getQueryString|executeQuery|executeUpdate|readObject|getInstance|"
    r"new\s+File|FileInputStream|ObjectInputStream|ProcessBuilder|getRuntime|"
    r"getWriter|println|sendRedirect|doGet|doPost|Cipher|MessageDigest"
)
_WINDOW_PAD_LINES = 20


@dataclass(frozen=True)
class RenderedPrompt:
    """Rendered user prompt plus audit metadata recorded on the trial."""

    text: str
    prompt_chars: int
    truncated: bool
    slice_strategy: str  # "full" | "evidence_window" | "sink_window" | "head_window"
    window_start: int
    window_end: int
    n_lines: int


def render_prompt(
    unit: SeedUnit,
    evidence: list[Evidence],
    hits: list[RankedHit],
    max_chars: int | None = None,
) -> RenderedPrompt:
    budget = max_chars or settings.prompt_max_chars
    lines = unit.source.splitlines()
    start, end, strategy = _choose_window(lines, evidence, budget)
    excerpt = _prefixed(lines, start, end)
    truncated = strategy != "full"
    window_note = (
        f"lines 1-{len(lines)} of {len(lines)}"
        if not truncated
        else f"showing lines {start}-{end} of {len(lines)}; cite absolute line numbers"
    )
    evidence_payload = [item.to_dict() for item in evidence]
    hits_payload = [
        {
            "cwe_id": hit.cwe_id,
            "score": hit.score,
            "name": hit.name,
            **({"passage": hit.passage} if getattr(hit, "passage", "") else {}),
        }
        for hit in hits
    ]
    allowed = list(dict.fromkeys([hit.cwe_id for hit in hits] + [item.cwe_id for item in evidence]))
    allowed_text = ", ".join(allowed) if allowed else "(none — still never emit CWE-0)"
    text = USER_PROMPT.format(
        unit_id=unit.unit_id,
        path=unit.path,
        allowed_cwe_ids=allowed_text,
        window_note=window_note,
        source=excerpt,
        evidence=json.dumps(evidence_payload, indent=2),
        hits=json.dumps(hits_payload, indent=2),
    )
    return RenderedPrompt(
        text=text,
        prompt_chars=len(text),
        truncated=truncated,
        slice_strategy=strategy,
        window_start=start,
        window_end=end,
        n_lines=len(lines),
    )


def render_user_prompt(
    unit: SeedUnit,
    evidence: list[Evidence],
    hits: list[RankedHit],
    max_chars: int | None = None,
) -> str:
    """Back-compatible wrapper returning only the prompt text."""
    return render_prompt(unit, evidence, hits, max_chars).text


def _prefixed(lines: list[str], start: int, end: int) -> str:
    return "\n".join(f"{n:>4}| {lines[n - 1]}" for n in range(start, end + 1))


def _choose_window(
    lines: list[str],
    evidence: list[Evidence],
    budget: int,
) -> tuple[int, int, str]:
    """Pick a 1-based inclusive line window that fits the character budget."""
    total = _excerpt_len(lines, 1, len(lines))
    if total <= budget:
        return 1, len(lines), "full"
    if evidence:
        lo = min(item.start_line for item in evidence)
        hi = max(item.end_line for item in evidence)
        start, end = _expand_window(lines, lo, hi, budget)
        return start, end, "evidence_window"
    sink_line = _first_sink_line(lines)
    if sink_line is not None:
        start, end = _expand_window(lines, sink_line, sink_line, budget)
        return start, end, "sink_window"
    end = 1
    while end < len(lines) and _excerpt_len(lines, 1, end + 1) <= budget:
        end += 1
    return 1, end, "head_window"


def _expand_window(lines: list[str], lo: int, hi: int, budget: int) -> tuple[int, int]:
    start = max(1, lo - _WINDOW_PAD_LINES)
    end = min(len(lines), hi + _WINDOW_PAD_LINES)
    # Shrink toward the core while over budget, trimming the side farther from it.
    while (end - start) > 1 and _excerpt_len(lines, start, end) > budget:
        trim_top = start < lo
        trim_bottom = end > hi
        if trim_top and (not trim_bottom or (lo - start) >= (end - hi)):
            start += 1
        elif trim_bottom:
            end -= 1
        elif trim_top:
            start += 1
        else:
            break  # the core alone exceeds the budget; keep it whole
    # Grow back symmetrically while there is budget left.
    while start > 1 and _excerpt_len(lines, start - 1, end) <= budget:
        start -= 1
    while end < len(lines) and _excerpt_len(lines, start, end + 1) <= budget:
        end += 1
    return start, end


def _excerpt_len(lines: list[str], start: int, end: int) -> int:
    # +6 per line for the "NNNN| " prefix and newline.
    return sum(len(lines[n - 1]) + 7 for n in range(start, end + 1))


def _first_sink_line(lines: list[str]) -> int | None:
    for index, line in enumerate(lines, start=1):
        if _SINK_HINT.search(line):
            return index
    return None
