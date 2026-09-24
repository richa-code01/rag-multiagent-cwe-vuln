"""Stanford Securibench Micro adapter (Livshits servlet microbenchmarks)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from cwe_vuln.config import repo_root
from cwe_vuln.dataset.common import (
    SuiteError,
    benchmarks_dir,
    cwe_coverage,
    git_head,
    label_counts,
    make_unit,
    relpath,
    sparse_clone,
    utc_now,
    write_json,
)
from cwe_vuln.dataset.seed import SeedUnit

SUITE = "securibench-micro"
GITHUB = "https://github.com/too4words/securibench-micro.git"
MICRO = Path("src/securibench/micro")
LICENSE_NOTE = "Apache-2.0 (Copyright 2006 Benjamin Livshits / Stanford Securibench Micro)."
SKIP_NAMES = {"BasicTestCase.java", "MicroTestCase.java"}
DESC = re.compile(r'@servlet description\s*=\s*"([^"]+)"')
VULN_DOC = re.compile(r'@servlet vuln_count\s*=\s*"(\d+)"')
VULN_RET = re.compile(r"getVulnerabilityCount\(\)\s*\{[^}]*return\s+(\d+)", re.S)


def suite_root(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "securibench-micro"


def provenance_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "securibench_micro_provenance.json"


def sample_manifest_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "securibench-micro_llm_sample.json"


def ensure_securibench(root: Path | None = None) -> dict[str, Any]:
    dest = suite_root(root)
    micro = dest / MICRO
    if micro.is_dir() and any(micro.rglob("*.java")):
        prov = {
            "suite": SUITE,
            "source_url": GITHUB,
            "downloaded_at": utc_now(),
            "method": "cached",
            "sha256_or_commit": git_head(dest) if (dest / ".git").exists() else "",
            "license_note": LICENSE_NOTE,
        }
        write_json(provenance_path(root), prov)
        return prov
    commit = sparse_clone(GITHUB, dest, [str(MICRO), "README.md"])
    prov = {
        "suite": SUITE,
        "source_url": GITHUB,
        "downloaded_at": utc_now(),
        "method": "github_sparse_clone",
        "sha256_or_commit": commit,
        "license_note": LICENSE_NOTE,
        "version": "1.08 (repo as cloned)",
    }
    write_json(provenance_path(root), prov)
    return prov


def _cwe_from_source(source: str, description: str) -> str | None:
    blob = f"{description}\n{source}".lower()
    if "sql injection" in blob or "prepared statement" in blob:
        return "CWE-89"
    if "path traversal" in blob or "directory traversal" in blob:
        return "CWE-22"
    if re.search(r"\b(statement|executequery|executeupdate)\b", blob) and "java.sql" in blob:
        return "CWE-89"
    if re.search(r"\bnew file\s*\(|fileinputstream|randomaccessfile|getrealpath\b", blob):
        return "CWE-22"
    if "xss" in blob or "printwriter" in blob or "getwriter" in blob:
        return "CWE-79"
    return None


def load_securibench_units(
    root: Path | None = None,
    *,
    tree: Path | None = None,
    require_download: bool = False,
) -> list[SeedUnit]:
    base = root or repo_root()
    src = tree if tree is not None else suite_root(base) / MICRO
    if require_download and tree is None:
        ensure_securibench(base)
        src = suite_root(base) / MICRO
    if not src.is_dir():
        raise SuiteError(f"Securibench micro tree not found: {src}")
    units: list[SeedUnit] = []
    skipped_no_cwe = 0
    for java in sorted(src.rglob("*.java")):
        if java.name in SKIP_NAMES:
            continue
        source = java.read_text(encoding="utf-8", errors="replace")
        desc_m = DESC.search(source)
        description = desc_m.group(1) if desc_m else ""
        vuln_m = VULN_DOC.search(source) or VULN_RET.search(source)
        if vuln_m is None:
            continue
        count = int(vuln_m.group(1))
        cwe_id = _cwe_from_source(source, description)
        if cwe_id is None:
            skipped_no_cwe += 1
            continue
        label = "vulnerable" if count > 0 else "not_vulnerable"
        units.append(
            make_unit(
                suite=SUITE,
                unit_id=f"sbmicro_{java.stem}",
                cwe_id=cwe_id,
                path=relpath(java, base),
                label=label,
                source=source,
                notes=f"securibench vuln_count={count} desc={description!r}",
            )
        )
    if not units:
        raise SuiteError(f"No Securibench units parsed from {src} (skipped_no_cwe={skipped_no_cwe})")
    return units


def mapping_notes(units: list[SeedUnit] | None = None) -> dict[str, Any]:
    notes: dict[str, Any] = {
        "gold": "@servlet vuln_count / getVulnerabilityCount(); 0 = not_vulnerable",
        "cwe": (
            "From @servlet description keywords (XSS/SQL/path) else Java sink APIs "
            "(java.sql → 89, File/getRealPath → 22, PrintWriter/getWriter → 79). "
            "HTTP-splitting and other non-thesis families are skipped, not relabeled."
        ),
        "cwe_coverage_plan": {
            "CWE-89": "SQL injection descriptions / java.sql sinks",
            "CWE-79": "XSS descriptions / writer sinks (majority of suite)",
            "CWE-22": "path traversal descriptions / File sinks",
            "CWE-502": "not present",
            "CWE-798": "not present",
            "CWE-327": "not present",
        },
        "license_note": LICENSE_NOTE,
    }
    if units is not None:
        notes["cwe_coverage"] = cwe_coverage(units)
        notes["per_cwe_n"] = label_counts(units)
    return notes
