"""Find Security Bugs Java plugin test-code adapter (file-level gold)."""

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

SUITE = "find-sec-bugs"
GITHUB = "https://github.com/find-sec-bugs/find-sec-bugs.git"
SAMPLES = Path("findsecbugs-samples-java/src/test/java/testcode")
LICENSE_NOTE = (
    "Find Security Bugs plugin samples (LGPL-style SpotBugs plugin project). "
    "Test-code is for detector tests, not a scored AST benchmark CSV."
)

# Directory (posix prefix under testcode/) → gold CWE. Do not ingest other families.
FOLDER_CWE: tuple[tuple[str, str], ...] = (
    ("sqli/", "CWE-89"),
    ("xss/", "CWE-79"),
    ("wicket/", "CWE-79"),
    ("pathtraversal/", "CWE-22"),
    ("file/", "CWE-22"),
    ("serial/", "CWE-502"),
    ("password/", "CWE-798"),
    ("potential/", "CWE-798"),
)

CRYPTO_VULN_STEMS = {
    "WeakMessageDigest",
    "WeakMessageDigestAdditionalSig",
    "DesKeyGeneration",
}
SAFE_MARKERS = (
    "safe",
    "falsepositive",
    "false_positive",
    "ok",
    "desirenowarning",
)


def suite_root(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "find-sec-bugs"


def provenance_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "find_sec_bugs_provenance.json"


def sample_manifest_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "find-sec-bugs_llm_sample.json"


def ensure_findsecbugs(root: Path | None = None) -> dict[str, Any]:
    dest = suite_root(root)
    samples = dest / SAMPLES
    if samples.is_dir() and any(samples.rglob("*.java")):
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
    commit = sparse_clone(GITHUB, dest, [str(SAMPLES), "README.md"])
    prov = {
        "suite": SUITE,
        "source_url": GITHUB,
        "downloaded_at": utc_now(),
        "method": "github_sparse_clone",
        "sha256_or_commit": commit,
        "license_note": LICENSE_NOTE,
    }
    write_json(provenance_path(root), prov)
    return prov


def _cwe_for(rel: str, stem: str) -> str | None:
    posix = rel.replace("\\", "/")
    for folder, cwe in FOLDER_CWE:
        if posix.startswith(folder) or f"/{folder}" in posix:
            if folder == "potential/" and "password" not in stem.lower() and "hardcode" not in stem.lower():
                continue
            if folder == "wicket/" and "xss" not in stem.lower():
                continue
            return cwe
    if posix.startswith("crypto/") or "/crypto/" in posix:
        if stem in CRYPTO_VULN_STEMS:
            return "CWE-327"
    return None


def _is_safe(stem: str, posix: str) -> bool:
    blob = f"{stem} {posix}".lower()
    return any(marker in blob for marker in SAFE_MARKERS)


def load_findsecbugs_units(
    root: Path | None = None,
    *,
    tree: Path | None = None,
    require_download: bool = False,
) -> list[SeedUnit]:
    base = root or repo_root()
    src = tree if tree is not None else suite_root(base) / SAMPLES
    if require_download and tree is None:
        ensure_findsecbugs(base)
        src = suite_root(base) / SAMPLES
    if not src.is_dir():
        raise SuiteError(f"find-sec-bugs samples not found: {src}")
    units: list[SeedUnit] = []
    for java in sorted(src.rglob("*.java")):
        if java.name == "package-info.java":
            continue
        rel = java.relative_to(src).as_posix()
        cwe_id = _cwe_for(rel, java.stem)
        if cwe_id is None:
            continue
        source = java.read_text(encoding="utf-8", errors="replace")
        label = "not_vulnerable" if _is_safe(java.stem, rel) else "vulnerable"
        units.append(
            make_unit(
                suite=SUITE,
                unit_id="fsb_" + rel.replace("/", "_").removesuffix(".java"),
                cwe_id=cwe_id,
                path=relpath(java, base),
                label=label,
                source=source,
                notes=f"find-sec-bugs testcode/{rel} file-level gold",
            )
        )
    if not units:
        raise SuiteError(f"No find-sec-bugs mapped units from {src}")
    return units


def mapping_notes(units: list[SeedUnit] | None = None) -> dict[str, Any]:
    notes: dict[str, Any] = {
        "gold": (
            "File-level: plugin samples under testcode/. "
            "Safe/FalsePositive/Ok filenames → not_vulnerable; other mapped files → vulnerable. "
            "Mixed methods in one class are not split."
        ),
        "folders": {folder: cwe for folder, cwe in FOLDER_CWE},
        "crypto": f"only stems {sorted(CRYPTO_VULN_STEMS)} mapped to CWE-327; other crypto samples skipped",
        "cwe_coverage_plan": {
            "CWE-89": "testcode/sqli",
            "CWE-79": "testcode/xss (+ wicket XSS pages)",
            "CWE-22": "testcode/pathtraversal, file",
            "CWE-502": "testcode/serial",
            "CWE-798": "testcode/password (+ potential hardcoded password)",
            "CWE-327": "WeakMessageDigest / DesKeyGeneration only",
        },
        "license_note": LICENSE_NOTE,
    }
    if units is not None:
        notes["cwe_coverage"] = cwe_coverage(units)
        notes["per_cwe_n"] = label_counts(units)
    return notes
