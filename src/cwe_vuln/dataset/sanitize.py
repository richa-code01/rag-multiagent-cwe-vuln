"""Prompt-side sanitization: strip gold-label leakage before any LLM sees a unit.

Public-benchmark adapters leak ground truth into prompts: Juliet ``bad``/``good*``
method names, ``/* POTENTIAL FLAW */`` / ``/* FIX: */`` comments, CWE folder names
in paths and class names, Vul4J/CVEfixes ``_vuln``/``_fixed`` id suffixes, and
authored ids that embed the gold CWE (``java_cwe89_*``). This module rewrites a
SeedUnit into a prompt-safe copy while PRESERVING line numbers (comments are
blanked, not deleted; identifiers are renamed in place), so line numbers cited by
the LLM still map to the original source on disk.

Scoring metadata (``label``, ``cwe_id``, ``split``) stays on the returned object
for the evaluation loop, but none of it is reachable from the rendered prompt:
the prompt only sees the opaque id, a neutral path, and the sanitized source.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import replace

from cwe_vuln.dataset.seed import SeedUnit

# Substrings that must never appear in an LLM prompt copy. Lower-cased compare.
GOLD_TOKENS: tuple[str, ...] = (
    "flaw",
    "fix:",
    "potential flaw",
    "method_bad",
    "method_good",
    "file_bad",
    "file_good",
    "_bad",
    "_good",
    "real=true",
    "real=false",
)

# Regex tokens needing boundaries: ``_vuln``/``_fixed`` id suffixes must not match
# the legitimate schema words "not_vulnerable" / "vulnerable".
GOLD_TOKEN_REGEXES: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<!not)_vuln(?!erable)", re.IGNORECASE),
    re.compile(r"_fixed\b", re.IGNORECASE),
)


def find_gold_tokens(text: str) -> list[str]:
    """Return the gold tokens present in text (used by tests and prompt audits)."""
    lowered = text.lower()
    found = [token for token in GOLD_TOKENS if token in lowered]
    for pattern in GOLD_TOKEN_REGEXES:
        if pattern.search(text):
            found.append(pattern.pattern)
    return found

_CWE_CLASS = re.compile(r"\b[Cc][Ww][Ee]\d+[_A-Za-z0-9]*\b")
_BAD_IDENT = re.compile(r"\bbad([A-Za-z0-9_]*)\b")
_GOOD_IDENT = re.compile(r"\bgood([A-Za-z0-9_]*)\b")


def opaque_unit_id(unit_id: str) -> str:
    """Stable opaque prompt id: no CWE number, no bad/good/vuln/fixed suffix."""
    return "unit_" + hashlib.sha1(unit_id.encode("utf-8")).hexdigest()[:12]


def sanitize_unit(unit: SeedUnit, *, display_path: str = "Snippet.java") -> SeedUnit:
    """Return a prompt-safe copy: opaque id, neutral path, sanitized source.

    Line count and line order are preserved so absolute line numbers cited by
    the LLM still resolve against ``unit.source`` on disk.
    """
    return replace(
        unit,
        unit_id=opaque_unit_id(unit.unit_id),
        path=display_path,
        notes="",
        source=sanitize_source(unit.source),
    )


def retrieval_query_text(unit: SeedUnit, *, max_chars: int | None = None, pad: int = 20) -> str:
    """Source window used as the retrieval query: evidence or sink, not file head.

    Aligns MiniLM/TF-IDF with the same region the LLM prompt prefers. Line numbers
    are not re-based (unlike ``slice_unit``); this is a query string only.
    """
    from cwe_vuln.config import settings
    from cwe_vuln.sast import extract_evidence

    budget = max_chars if max_chars is not None else settings.retrieval_query_chars
    lines = unit.source.splitlines() or [""]
    evidence = extract_evidence(unit)
    if evidence:
        lo = max(1, min(item.start_line for item in evidence) - pad)
        hi = min(len(lines), max(item.end_line for item in evidence) + pad)
    else:
        from cwe_vuln.reasoner.prompts import _first_sink_line

        sink = _first_sink_line(lines)
        if sink is None:
            return unit.source[:budget]
        lo = max(1, sink - pad)
        hi = min(len(lines), sink + pad)
    window = "\n".join(lines[lo - 1 : hi])
    return window[:budget]


def slice_unit(unit: SeedUnit, *, pad: int = 40) -> SeedUnit:
    """Keep a window around SAST/sink lines so real-world files stay prompt-sized.

    Used for Vul4J/CVEfixes (C3). Line numbers inside the window are re-based to 1
    because the sliced source *is* the unit the LLM and validator see.
    """
    from cwe_vuln.sast import extract_evidence

    lines = unit.source.splitlines() or [""]
    evidence = extract_evidence(unit)
    if evidence:
        lo = max(1, min(item.start_line for item in evidence) - pad)
        hi = min(len(lines), max(item.end_line for item in evidence) + pad)
        strategy = "evidence_window"
    else:
        from cwe_vuln.reasoner.prompts import _first_sink_line

        sink = _first_sink_line(lines)
        if sink is None:
            return unit
        lo = max(1, sink - pad)
        hi = min(len(lines), sink + pad)
        strategy = "sink_window"
    window = "\n".join(lines[lo - 1 : hi])
    notes = f"{unit.notes} slice={strategy} orig_lines={lo}-{hi}".strip()
    return replace(unit, source=window, notes=notes)


def sanitize_source(source: str) -> str:
    """Blank comments and rename gold-hint identifiers, preserving line numbers."""
    return _rewrite_code(source, _rename_identifiers)


def _rename_identifiers(code: str) -> str:
    code = _BAD_IDENT.sub(r"entry\1", code)
    code = _GOOD_IDENT.sub(r"alt\1", code)
    return _CWE_CLASS.sub(_class_replacer(), code)


def _class_replacer():
    mapping: dict[str, str] = {}

    def _sub(match: re.Match[str]) -> str:
        token = match.group(0)
        if token not in mapping:
            mapping[token] = f"Snippet{len(mapping) + 1}"
        return mapping[token]

    return _sub


def _rewrite_code(source: str, transform) -> str:
    """Apply ``transform`` to code segments only; blank comments; keep strings verbatim.

    Newlines are always preserved so line numbers are stable.
    """
    out: list[str] = []
    code_buf: list[str] = []
    i, n = 0, len(source)
    state = "code"

    def flush_code() -> None:
        if code_buf:
            out.append(transform("".join(code_buf)))
            code_buf.clear()

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                flush_code()
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                flush_code()
                state = "block_comment"
                i += 2
                continue
            if ch == '"':
                flush_code()
                state = "string"
                out.append(ch)
                i += 1
                continue
            if ch == "'":
                flush_code()
                state = "char"
                out.append(ch)
                i += 1
                continue
            code_buf.append(ch)
            i += 1
            continue
        if state == "string":
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(source[i + 1])
                i += 2
                continue
            if ch == '"':
                state = "code"
            i += 1
            continue
        if state == "char":
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(source[i + 1])
                i += 2
                continue
            if ch == "'":
                state = "code"
            i += 1
            continue
        if state == "line_comment":
            if ch == "\n":
                out.append("\n")
                state = "code"
            else:
                out.append(" ")
            i += 1
            continue
        # block_comment
        if ch == "*" and nxt == "/":
            out.append("  ")
            i += 2
            state = "code"
            continue
        out.append("\n" if ch == "\n" else " ")
        i += 1
    flush_code()
    return "".join(out)
