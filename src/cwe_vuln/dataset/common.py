"""Shared helpers for public Java suite adapters (download, provenance, sampling)."""

from __future__ import annotations

import json
import os
import random
import re
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cwe_vuln.config import repo_root
from cwe_vuln.dataset.seed import SeedUnit

THESIS_CWES: tuple[str, ...] = (
    "CWE-89",
    "CWE-79",
    "CWE-22",
    "CWE-502",
    "CWE-798",
    "CWE-327",
)
SAMPLE_SEED = 13
DEFAULT_SUITE_SAMPLE_N = 12


class SuiteError(RuntimeError):
    """Raised when a public suite cannot be located or parsed."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def benchmarks_dir(root: Path | None = None) -> Path:
    return (root or repo_root()) / "data" / "benchmarks"


def write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def make_unit(
    *,
    suite: str,
    unit_id: str,
    cwe_id: str,
    path: str,
    label: str,
    source: str,
    notes: str,
) -> SeedUnit:
    return SeedUnit(
        unit_id=unit_id,
        cwe_id=cwe_id,
        path=path,
        split=suite,  # type: ignore[arg-type]
        label=label,  # type: ignore[arg-type]
        notes=notes,
        source=source,
        trap_type=suite,
        corpus=suite,
    )


def relpath(path: Path, repo: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo.resolve()))
    except ValueError:
        return str(path)


def git_head(tree: Path) -> str:
    rev = subprocess.run(
        ["git", "-C", str(tree), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return rev.stdout.strip()


def sparse_clone(
    url: str,
    dest: Path,
    paths: list[str],
    *,
    depth: int = 1,
) -> str:
    if dest.exists() and (dest / ".git").exists() and git_head(dest):
        return git_head(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        subprocess.run(["rm", "-rf", str(dest)], check=True)
    cmd = [
        "git",
        "clone",
        "--filter=blob:none",
        "--sparse",
        "--depth",
        str(depth),
        url,
        str(dest),
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    sparse = ["git", "-C", str(dest), "sparse-checkout", "set", "--skip-checks", *paths]
    subprocess.run(sparse, check=True, capture_output=True, text=True)
    return git_head(dest)


def cwe_coverage(units: list[SeedUnit]) -> dict[str, Any]:
    present = {unit.cwe_id for unit in units}
    return {
        cwe: ("present" if cwe in present else "not present")
        for cwe in THESIS_CWES
    }


def label_counts(units: list[SeedUnit]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for unit in units:
        bucket = out.setdefault(unit.cwe_id, {"vulnerable": 0, "not_vulnerable": 0, "n": 0})
        bucket[unit.label] += 1
        bucket["n"] += 1
    return out


def stratified_suite_sample(
    units: list[SeedUnit],
    *,
    n: int = DEFAULT_SUITE_SAMPLE_N,
    seed: int = SAMPLE_SEED,
) -> list[SeedUnit]:
    """Deterministic sample of about n units, round-robin over CWE × label."""
    if not units:
        return []
    if len(units) <= n:
        return sorted(units, key=lambda item: item.unit_id)
    rng = random.Random(seed)
    grouped: dict[tuple[str, str], list[SeedUnit]] = {}
    for unit in units:
        grouped.setdefault((unit.cwe_id, unit.label), []).append(unit)
    for key in grouped:
        rng.shuffle(grouped[key])
    keys = sorted(grouped)
    sampled: list[SeedUnit] = []
    seen: set[str] = set()
    index = 0
    while len(sampled) < n:
        progressed = False
        for key in keys:
            bucket = grouped[key]
            if index >= len(bucket):
                continue
            unit = bucket[index]
            if unit.unit_id not in seen:
                sampled.append(unit)
                seen.add(unit.unit_id)
                progressed = True
                if len(sampled) >= n:
                    break
        if not progressed:
            break
        index += 1
    sampled.sort(key=lambda item: item.unit_id)
    return sampled


def write_sample_manifest(
    suite: str,
    units: list[SeedUnit],
    path: Path,
    *,
    n_target: int,
    seed: int,
    provenance: dict[str, Any] | None = None,
) -> Path:
    payload = {
        "suite": suite,
        "seed": seed,
        "n_target": n_target,
        "n_units": len(units),
        "per_cwe_counts": label_counts(units),
        "cwe_coverage": cwe_coverage(units),
        "provenance": provenance,
        "unit_ids": [unit.unit_id for unit in units],
        "units": [
            {
                "unit_id": unit.unit_id,
                "cwe_id": unit.cwe_id,
                "label": unit.label,
                "path": unit.path,
            }
            for unit in units
        ],
    }
    return write_json(path, payload)


def load_sample_units(units: list[SeedUnit], manifest: Path) -> list[SeedUnit]:
    if not manifest.is_file():
        raise SuiteError(f"Missing LLM sample manifest: {manifest}")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    wanted = list(payload["unit_ids"])
    index = {unit.unit_id: unit for unit in units}
    missing = [uid for uid in wanted if uid not in index]
    if missing:
        raise SuiteError(f"Sample ids not in loaded units: {missing[:8]}")
    return [index[uid] for uid in wanted]


def github_token() -> str | None:
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    try:
        proc = subprocess.run(
            ["gh", "auth", "token"],
            check=False,
            capture_output=True,
            text=True,
        )
        token = proc.stdout.strip()
        if proc.returncode == 0 and token:
            return token
    except OSError:
        pass
    try:
        proc = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            check=False,
            capture_output=True,
            text=True,
        )
        match = re.search(r"password=(\S+)", proc.stdout)
        if match:
            return match.group(1)
    except OSError:
        pass
    return None


def http_json(url: str, *, accept: str = "application/vnd.github+json") -> Any:
    return json.loads(http_bytes(url, accept=accept).decode("utf-8"))


def http_text(url: str, *, accept: str = "*/*") -> str:
    return http_bytes(url, accept=accept).decode("utf-8", errors="replace")


def http_bytes(url: str, *, accept: str = "*/*", retries: int = 4) -> bytes:
    token = github_token() if "github.com" in url or "api.github.com" in url else None
    headers = {
        "User-Agent": "cwe-vuln-thesis-eval",
        "Accept": accept,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    last_error: Exception | None = None
    for attempt in range(retries):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code in {403, 429, 502, 503} and attempt + 1 < retries:
                time.sleep(2 ** attempt)
                continue
            raise
        except urllib.error.URLError as exc:
            last_error = exc
            if attempt + 1 < retries:
                time.sleep(2 ** attempt)
                continue
            raise
    raise SuiteError(f"HTTP failed for {url}: {last_error}")
