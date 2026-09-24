"""CVEfixes-Java-slice: GitHub Advisory maven CVEs with gold CWE + Java patches.

This is a documented slice, not the full CVEfixes SQLite dump.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cwe_vuln.config import repo_root
from cwe_vuln.dataset.common import (
    THESIS_CWES,
    SuiteError,
    benchmarks_dir,
    cwe_coverage,
    http_json,
    http_text,
    label_counts,
    make_unit,
    utc_now,
    write_json,
)
from cwe_vuln.dataset.seed import SeedUnit

SUITE = "cvefixes-java-slice"
LICENSE_NOTE = (
    "Slice constructed from public GitHub Security Advisories (ecosystem=maven) "
    "plus referenced GitHub commits. Named CVEfixes-Java-slice because the full "
    "CVEfixes (Zenodo/SQLite) dump is too large to vendor; gold CWE comes from "
    "the advisory CWE list. Not the complete CVEfixes database."
)
COMMIT_RE = re.compile(r"https://github.com/([^/]+/[^/]+)/commit/([0-9a-fA-F]{7,40})")
# Cap pages so we stay a slice, not a dump.
ADVISORY_PAGES = 3
PER_PAGE = 100
MAX_ADVISORIES = 24
MAX_FILES_PER_COMMIT = 4


def slice_root(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "cvefixes-files"


def provenance_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "cvefixes_java_slice_provenance.json"


def sample_manifest_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "cvefixes-java-slice_llm_sample.json"


def manifest_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "cvefixes_java_slice_manifest.json"


def _cwe_from_advisory(item: dict[str, Any]) -> str | None:
    for cwe in item.get("cwes") or []:
        cid = str(cwe.get("cwe_id") or "").strip()
        if cid in THESIS_CWES:
            return cid
    return None


def _commit_urls(item: dict[str, Any]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for url in item.get("references") or []:
        match = COMMIT_RE.search(str(url))
        if match:
            found.append((match.group(1), match.group(2)))
    return found


def ensure_cvefixes_slice(root: Path | None = None) -> dict[str, Any]:
    """Fetch advisory metadata if the committed/cached manifest is missing."""
    path = manifest_path(root)
    if path.is_file():
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload.setdefault("method", "cached_manifest")
        write_json(provenance_path(root), {k: payload.get(k) for k in (
            "suite", "source_url", "downloaded_at", "method", "sha256_or_commit", "license_note", "n_advisories"
        ) if k in payload} | {
            "suite": SUITE,
            "source_url": payload.get("source_url", "https://api.github.com/advisories"),
            "downloaded_at": payload.get("downloaded_at", utc_now()),
            "method": payload.get("method", "cached_manifest"),
            "sha256_or_commit": payload.get("sha256_or_commit", ""),
            "license_note": LICENSE_NOTE,
        })
        return payload
    records: list[dict[str, Any]] = []
    for page in range(1, ADVISORY_PAGES + 1):
        url = (
            "https://api.github.com/advisories?"
            f"ecosystem=maven&per_page={PER_PAGE}&page={page}"
        )
        batch = http_json(url)
        if not isinstance(batch, list) or not batch:
            break
        for item in batch:
            cwe = _cwe_from_advisory(item)
            if cwe is None:
                continue
            commits = _commit_urls(item)
            if not commits:
                continue
            records.append(
                {
                    "ghsa_id": item.get("ghsa_id"),
                    "cve_id": item.get("cve_id"),
                    "cwe_id": cwe,
                    "summary": item.get("summary"),
                    "html_url": item.get("html_url"),
                    "published_at": item.get("published_at"),
                    "commits": [{"slug": slug, "sha": sha} for slug, sha in commits[:2]],
                }
            )
            if len(records) >= MAX_ADVISORIES:
                break
        if len(records) >= MAX_ADVISORIES:
            break
    payload = {
        "suite": SUITE,
        "source_url": "https://api.github.com/advisories?ecosystem=maven",
        "downloaded_at": utc_now(),
        "method": "github_advisories_maven_slice",
        "sha256_or_commit": f"n_advisories={len(records)} pages<={ADVISORY_PAGES}",
        "license_note": LICENSE_NOTE,
        "n_advisories": len(records),
        "advisories": records,
    }
    write_json(path, payload)
    write_json(provenance_path(root), {
        "suite": SUITE,
        "source_url": payload["source_url"],
        "downloaded_at": payload["downloaded_at"],
        "method": payload["method"],
        "sha256_or_commit": payload["sha256_or_commit"],
        "license_note": LICENSE_NOTE,
        "n_advisories": len(records),
    })
    return payload


def _load_fixture_units(tree: Path, base: Path) -> list[SeedUnit]:
    units: list[SeedUnit] = []
    for java in sorted(tree.rglob("*.java")):
        name = java.name.lower()
        source = java.read_text(encoding="utf-8", errors="replace")
        label = "not_vulnerable" if "fixed" in name or "good" in name else "vulnerable"
        cwe_match = re.search(r"CWE-?(\d+)", java.stem + source[:400], re.I)
        cwe_id = f"CWE-{int(cwe_match.group(1))}" if cwe_match else "CWE-89"
        units.append(
            make_unit(
                suite=SUITE,
                unit_id=f"cveslice_{java.stem}",
                cwe_id=cwe_id,
                path=str(java.relative_to(tree)),
                label=label,
                source=source,
                notes="cvefixes-java-slice fixture",
            )
        )
    return units


def load_cvefixes_units(
    root: Path | None = None,
    *,
    tree: Path | None = None,
    require_download: bool = False,
    fetch_patches: bool = True,
) -> list[SeedUnit]:
    base = root or repo_root()
    if tree is not None:
        units = _load_fixture_units(tree, base)
        if not units:
            raise SuiteError(f"No CVEfixes-Java-slice fixture units in {tree}")
        return units
    payload = ensure_cvefixes_slice(base) if require_download or manifest_path(base).is_file() else ensure_cvefixes_slice(base)
    dest = slice_root(base)
    dest.mkdir(parents=True, exist_ok=True)
    units: list[SeedUnit] = []
    errors: list[str] = []
    for rec in payload.get("advisories") or []:
        cwe = rec["cwe_id"]
        ghsa = rec.get("ghsa_id") or "unknown"
        for commit in rec.get("commits") or []:
            slug, sha = commit["slug"], commit["sha"]
            local = dest / ghsa / sha[:12]
            local.mkdir(parents=True, exist_ok=True)
            try:
                if fetch_patches:
                    info = http_json(f"https://api.github.com/repos/{slug}/commits/{sha}")
                    parent = info["parents"][0]["sha"]
                    java_files = [
                        item["filename"]
                        for item in info.get("files") or []
                        if str(item.get("filename", "")).endswith(".java")
                        and item.get("status") != "added"
                    ][:MAX_FILES_PER_COMMIT]
                else:
                    parent = ""
                    java_files = []
            except Exception as exc:
                errors.append(f"{ghsa} {slug}@{sha}: {exc}")
                java_files = []
                parent = ""
                info = {"files": []}
            if not java_files:
                for vuln_p in sorted(local.glob("*.vuln.java")):
                    fix_p = local / vuln_p.name.replace(".vuln.java", ".fixed.java")
                    stem = vuln_p.name.replace(".vuln.java", "")
                    units.append(
                        make_unit(
                            suite=SUITE,
                            unit_id=f"cveslice_{ghsa}_{stem}_vuln",
                            cwe_id=cwe,
                            path=stem.replace("__", "/"),
                            label="vulnerable",
                            source=vuln_p.read_text(encoding="utf-8", errors="replace"),
                            notes=f"{ghsa} {rec.get('cve_id')} cached",
                        )
                    )
                    if fix_p.is_file():
                        units.append(
                            make_unit(
                                suite=SUITE,
                                unit_id=f"cveslice_{ghsa}_{stem}_fixed",
                                cwe_id=cwe,
                                path=stem.replace("__", "/"),
                                label="not_vulnerable",
                                source=fix_p.read_text(encoding="utf-8", errors="replace"),
                                notes=f"{ghsa} {rec.get('cve_id')} cached fixed",
                            )
                        )
                continue
            for filename in java_files:
                safe = filename.replace("/", "__")
                try:
                    parent_src = http_text(
                        f"https://raw.githubusercontent.com/{slug}/{parent}/{quote(filename)}"
                    )
                except Exception:
                    continue
                try:
                    fixed_src = http_text(
                        f"https://raw.githubusercontent.com/{slug}/{sha}/{quote(filename)}"
                    )
                except Exception:
                    fixed_src = ""
                (local / f"{safe}.vuln.java").write_text(parent_src, encoding="utf-8")
                if fixed_src:
                    (local / f"{safe}.fixed.java").write_text(fixed_src, encoding="utf-8")
                units.append(
                    make_unit(
                        suite=SUITE,
                        unit_id=f"cveslice_{ghsa}_{Path(filename).stem}_vuln",
                        cwe_id=cwe,
                        path=filename,
                        label="vulnerable",
                        source=parent_src,
                        notes=f"{ghsa} {rec.get('cve_id')} parent of {sha}",
                    )
                )
                if fixed_src:
                    units.append(
                        make_unit(
                            suite=SUITE,
                            unit_id=f"cveslice_{ghsa}_{Path(filename).stem}_fixed",
                            cwe_id=cwe,
                            path=filename,
                            label="not_vulnerable",
                            source=fixed_src,
                            notes=f"{ghsa} {rec.get('cve_id')} patch {sha}",
                        )
                    )
            break  # one commit per advisory is enough for a slice
    if not units:
        raise SuiteError(
            "CVEfixes-Java-slice produced 0 units. GitHub Advisory fetch or commit "
            f"Java files failed. errors={errors[:6]}"
        )
    return units


def mapping_notes(units: list[SeedUnit] | None = None) -> dict[str, Any]:
    notes: dict[str, Any] = {
        "gold": "GitHub Advisory CWE list; parent blob = vulnerable, patch blob = fixed",
        "substitution": (
            "Not the full CVEfixes SQLite dump. Named CVEfixes-Java-slice. "
            "Exact n is the number of ingested Java file versions."
        ),
        "license_note": LICENSE_NOTE,
        "cwe_coverage_plan": {cwe: "present if an advisory+commit in the slice has that CWE else not present" for cwe in THESIS_CWES},
    }
    if units is not None:
        notes["cwe_coverage"] = cwe_coverage(units)
        notes["per_cwe_n"] = label_counts(units)
    return notes
