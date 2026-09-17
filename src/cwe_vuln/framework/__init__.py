"""Thin CLI: run the orchestrated pipeline on seed units and write metrics."""

from cwe_vuln.framework.cli import main, run_split
from cwe_vuln.framework.eval import main as eval_main

__all__ = ["eval_main", "main", "run_split"]
