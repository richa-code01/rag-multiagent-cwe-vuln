"""OWASP Benchmark Java adapter: one servlet file per expectedresults CSV row."""

from __future__ import annotations

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

SUITE = "owasp-benchmark"
GITHUB = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
CSV_NAME = "expectedresults-1.2.csv"
TESTCODE = Path("src/main/java/org/owasp/benchmark/testcode")
LICENSE_NOTE = (
    "OWASP Benchmark for Java (BenchmarkJava). Educational AST test suite; "
    "see the upstream repository license/README. Not redistributed in git."
)


def suite_root(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "owasp-benchmark"


def provenance_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "owasp_benchmark_provenance.json"


def sample_manifest_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "owasp-benchmark_llm_sample.json"


def ensure_owasp(root: Path | None = None) -> dict[str, Any]:
    dest = suite_root(root)
    csv_path = dest / CSV_NAME
    if csv_path.is_file() and (dest / TESTCODE).is_dir():
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
    commit = sparse_clone(
        GITHUB,
        dest,
        [str(TESTCODE), CSV_NAME, "README.md"],
    )
    prov = {
        "suite": SUITE,
        "source_url": GITHUB,
        "downloaded_at": utc_now(),
        "method": "github_sparse_clone",
        "sha256_or_commit": commit,
        "license_note": LICENSE_NOTE,
        "version_csv": CSV_NAME,
    }
    write_json(provenance_path(root), prov)
    return prov


def load_owasp_units(
    root: Path | None = None,
    *,
    tree: Path | None = None,
    require_download: bool = False,
) -> list[SeedUnit]:
    base = root or repo_root()
    src = tree if tree is not None else suite_root(base)
    if require_download and tree is None:
        ensure_owasp(base)
        src = suite_root(base)
    csv_path = src / CSV_NAME
    java_root = src / TESTCODE
    if not csv_path.is_file():
        raise SuiteError(f"OWASP expected results CSV not found: {csv_path}")
    units: list[SeedUnit] = []
    for line in csv_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = [item.strip() for item in stripped.split(",")]
        if len(parts) < 4:
            continue
        name, _category, real, cwe_num = parts[0], parts[1], parts[2], parts[3]
        if not cwe_num.isdigit():
            continue
        java = java_root / f"{name}.java"
        if not java.is_file():
            continue
        source = java.read_text(encoding="utf-8", errors="replace")
        label = "vulnerable" if real.lower() == "true" else "not_vulnerable"
        units.append(
            make_unit(
                suite=SUITE,
                unit_id=f"owasp_{name}",
                cwe_id=f"CWE-{int(cwe_num)}",
                path=relpath(java, base),
                label=label,
                source=source,
                notes=f"owasp csv {CSV_NAME} real={real} cwe={cwe_num}",
            )
        )
    if not units:
        raise SuiteError(f"No OWASP units parsed from {src}")
    return units


def mapping_notes(units: list[SeedUnit] | None = None) -> dict[str, Any]:
    notes: dict[str, Any] = {
        "gold": f"{CSV_NAME} columns: test name, category, real vulnerability, cwe",
        "unit": "one BenchmarkTest*.java file per CSV row",
        "cwe_coverage_plan": {
            "CWE-89": "present (sqli)",
            "CWE-79": "present (xss)",
            "CWE-22": "present (pathtraver)",
            "CWE-327": "present (crypto)",
            "CWE-328": "nearby hash category; not relabeled to 327",
            "CWE-502": "not present",
            "CWE-798": "not present",
        },
        "license_note": LICENSE_NOTE,
    }
    if units is not None:
        notes["cwe_coverage"] = cwe_coverage(units)
        notes["per_cwe_n"] = label_counts(units)
    return notes
