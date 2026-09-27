"""Build the CLI string the operator console shows before a run starts."""

from __future__ import annotations

from typing import Any


def command_for(spec: dict[str, Any]) -> str:
    kind = spec.get("kind") or "eval"
    if kind == "pipeline":
        parts = ["uv", "run", "cwe-vuln-pipeline", "--split", str(spec.get("split") or "test")]
        if spec.get("offline"):
            parts.append("--offline")
        return " ".join(parts)
    parts = ["uv", "run", "cwe-vuln-eval", "--suite", str(spec.get("suite") or "research")]
    ablation = str(spec.get("ablation") or "none")
    if spec.get("offline") or ablation == "template":
        parts.append("--offline")
    elif ablation == "skip-llm":
        parts.extend(["--ablation", "skip-llm"])
    if spec.get("resume"):
        parts.append("--resume")
    if spec.get("max_tokens"):
        parts.extend(["--max-tokens", str(int(spec["max_tokens"]))])
    if spec.get("include_model_ablation"):
        parts.append("--include-model-ablation")
    if spec.get("per_cwe"):
        parts.extend(["--per-cwe", str(int(spec["per_cwe"]))])
    if spec.get("sample_n"):
        parts.extend(["--sample-n", str(int(spec["sample_n"]))])
    return " ".join(parts)


def argv_for(spec: dict[str, Any]) -> list[str]:
    """Argv for ``cwe-vuln-eval`` or ``cwe-vuln-pipeline``, without the uv prefix."""
    kind = spec.get("kind") or "eval"
    if kind == "pipeline":
        argv = ["--split", str(spec.get("split") or "test")]
        if spec.get("offline"):
            argv.append("--offline")
        return argv
    argv = ["--suite", str(spec.get("suite") or "research")]
    ablation = str(spec.get("ablation") or "none")
    if spec.get("offline") or ablation == "template":
        argv.append("--offline")
    elif ablation == "skip-llm":
        argv.extend(["--ablation", "skip-llm"])
    if spec.get("resume"):
        argv.append("--resume")
    if spec.get("max_tokens"):
        argv.extend(["--max-tokens", str(int(spec["max_tokens"]))])
    if spec.get("include_model_ablation"):
        argv.append("--include-model-ablation")
    if spec.get("per_cwe"):
        argv.extend(["--per-cwe", str(int(spec["per_cwe"]))])
    if spec.get("sample_n"):
        argv.extend(["--sample-n", str(int(spec["sample_n"]))])
    if spec.get("sample_seed") is not None:
        argv.extend(["--sample-seed", str(int(spec["sample_seed"]))])
    return argv
