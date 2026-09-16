"""Orchestrate analyzer → CWE specialist → reporter."""

from __future__ import annotations

from cwe_rag.agents import Report, analyze, report, specialize


def detect(code: str) -> Report:
    finding = analyze(code)
    opinion = specialize(finding)
    return report(finding, opinion)
