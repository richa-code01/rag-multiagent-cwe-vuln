"""Vul4J adapter: CSV gold CWE + GitHub patch parent/commit Java files."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cwe_vuln.config import repo_root
from cwe_vuln.dataset.common import (
    THESIS_CWES,
    SuiteError,
    benchmarks_dir,
    cwe_coverage,
    git_head,
    http_json,
    http_text,
    label_counts,
    make_unit,
    sparse_clone,
    utc_now,
    write_json,
)
from cwe_vuln.dataset.seed import SeedUnit

SUITE = "vul4j"
GITHUB = "https://github.com/tuhh-softsec/vul4j.git"
CSV_REL = Path("dataset/vul4j_dataset.csv")
LICENSE_NOTE = (
    "Vul4J dataset (tuhh-softsec/vul4j), GPLv3 project metadata. "
    "Java snippets are fetched from upstream patch commits and are not vendored in git."
)
COMMIT_RE = re.compile(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-fA-F]+)")


def suite_root(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "vul4j"


def files_root(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "vul4j-files"


def provenance_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "vul4j_provenance.json"


def sample_manifest_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "vul4j_llm_sample.json"


def ensure_vul4j(root: Path | None = None) -> dict[str, Any]:
    dest = suite_root(root)
    csv_path = dest / CSV_REL
    if csv_path.is_file():
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
    commit = sparse_clone(GITHUB, dest, [str(CSV_REL.parent), "README.md", "LICENSE"])
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


def _parse_patch(url: str) -> tuple[str, str] | None:
    match = COMMIT_RE.search(url.replace("http://", "https://"))
    if not match:
        parsed = urlparse(url)
        parts = parsed.path.strip("/").split("/")
        if len(parts) >= 4 and parts[2] == "commit":
            return f"{parts[0]}/{parts[1]}", parts[3]
        return None
    return match.group(1), match.group(2)


def _fetch_pair(slug: str, sha: str, dest: Path) -> list[tuple[str, str, str, str]]:
    """Return (path, parent_source, fixed_source, parent_sha) for changed Java files."""
    api = f"https://api.github.com/repos/{slug}/commits/{sha}"
    payload = http_json(api)
    parent = payload["parents"][0]["sha"]
    files = payload.get("files") or []
    out: list[tuple[str, str, str, str]] = []
    for item in files:
        filename = str(item.get("filename") or "")
        if not filename.endswith(".java"):
            continue
        status = item.get("status")
        if status == "added":
            continue
        raw_parent = f"https://raw.githubusercontent.com/{slug}/{parent}/{filename}"
        raw_fixed = f"https://raw.githubusercontent.com/{slug}/{sha}/{filename}"
        try:
            parent_src = http_text(raw_parent)
        except Exception:
            continue
        try:
            fixed_src = http_text(raw_fixed) if status != "removed" else ""
        except Exception:
            fixed_src = ""
        safe_name = filename.replace("/", "__")
        (dest / f"{safe_name}.vuln.java").write_text(parent_src, encoding="utf-8")
        if fixed_src:
            (dest / f"{safe_name}.fixed.java").write_text(fixed_src, encoding="utf-8")
        out.append((filename, parent_src, fixed_src, parent))
    return out


def _load_vul4j_java_tree(tree: Path, base: Path) -> list[SeedUnit]:
    units: list[SeedUnit] = []
    for java in sorted(tree.rglob("*.java")):
        source = java.read_text(encoding="utf-8", errors="replace")
        name = java.name.lower()
        label = "not_vulnerable" if "fixed" in name or "good" in name else "vulnerable"
        match = re.search(r"CWE-?(\d+)", java.stem + source[:300], re.I)
        cwe_id = f"CWE-{int(match.group(1))}" if match else "CWE-79"
        units.append(
            make_unit(
                suite=SUITE,
                unit_id=f"vul4j_{java.stem}",
                cwe_id=cwe_id,
                path=str(java.relative_to(tree)),
                label=label,
                source=source,
                notes="vul4j fixture",
            )
        )
    if not units:
        raise SuiteError(f"No Vul4J fixture Java in {tree}")
    return units


def load_vul4j_units(
    root: Path | None = None,
    *,
    tree: Path | None = None,
    require_download: bool = False,
    fetch_patches: bool = True,
) -> list[SeedUnit]:
    base = root or repo_root()
    if tree is not None and any(tree.rglob("*.java")) and not (tree / CSV_REL).is_file() and not (tree / "vul4j_dataset.csv").is_file():
        return _load_vul4j_java_tree(tree, base)
    src = tree if tree is not None else suite_root(base)
    if require_download and tree is None:
        ensure_vul4j(base)
        src = suite_root(base)
    csv_path = src / CSV_REL
    if not csv_path.is_file():
        # fixture layout: labels.jsonl or csv at tree root
        alt = src / "vul4j_dataset.csv"
        csv_path = alt if alt.is_file() else csv_path
    if not csv_path.is_file():
        raise SuiteError(f"Vul4J CSV not found: {csv_path}")
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    units: list[SeedUnit] = []
    errors: list[str] = []
    cache = files_root(base)
    cache.mkdir(parents=True, exist_ok=True)
    for row in rows:
        cwe = str(row.get("cwe_id") or "").strip()
        if cwe not in THESIS_CWES:
            continue
        vul_id = str(row.get("vul_id") or row.get("no") or "unknown")
        patch = str(row.get("human_patch") or "")
        parsed = _parse_patch(patch)
        if parsed is None:
            errors.append(f"{vul_id}: unparsed patch URL")
            continue
        slug, sha = parsed
        local = cache / vul_id
        local.mkdir(parents=True, exist_ok=True)
        meta = local / "meta.json"
        pairs: list[tuple[str, str, str, str]]
        if meta.is_file() and not fetch_patches:
            stored = json.loads(meta.read_text(encoding="utf-8"))
            pairs = []
            for item in stored.get("files", []):
                vuln_p = local / item["vuln"]
                fix_p = local / item["fixed"]
                if not vuln_p.is_file():
                    continue
                pairs.append(
                    (
                        item["path"],
                        vuln_p.read_text(encoding="utf-8", errors="replace"),
                        fix_p.read_text(encoding="utf-8", errors="replace") if fix_p.is_file() else "",
                        stored.get("parent", ""),
                    )
                )
        else:
            try:
                pairs = _fetch_pair(slug, sha, local) if fetch_patches else []
            except Exception as exc:
                errors.append(f"{vul_id}: {exc}")
                # fall back to any cached files
                pairs = []
                for vuln_p in sorted(local.glob("*.vuln.java")):
                    fix_p = local / vuln_p.name.replace(".vuln.java", ".fixed.java")
                    pairs.append(
                        (
                            vuln_p.name.replace("__", "/").replace(".vuln.java", ""),
                            vuln_p.read_text(encoding="utf-8", errors="replace"),
                            fix_p.read_text(encoding="utf-8", errors="replace") if fix_p.is_file() else "",
                            "",
                        )
                    )
            write_json(
                meta,
                {
                    "vul_id": vul_id,
                    "cwe_id": cwe,
                    "slug": slug,
                    "sha": sha,
                    "files": [
                        {
                            "path": path,
                            "vuln": f"{path.replace('/', '__')}.vuln.java",
                            "fixed": f"{path.replace('/', '__')}.fixed.java",
                        }
                        for path, _v, _f, _p in pairs
                    ],
                },
            )
        for path, vuln_src, fixed_src, _parent in pairs:
            stem = Path(path).stem
            units.append(
                make_unit(
                    suite=SUITE,
                    unit_id=f"vul4j_{vul_id}_{stem}_vuln",
                    cwe_id=cwe,
                    path=path,
                    label="vulnerable",
                    source=vuln_src,
                    notes=f"{vul_id} {row.get('cve_id')} parent of {sha}",
                )
            )
            if fixed_src:
                units.append(
                    make_unit(
                        suite=SUITE,
                        unit_id=f"vul4j_{vul_id}_{stem}_fixed",
                        cwe_id=cwe,
                        path=path,
                        label="not_vulnerable",
                        source=fixed_src,
                        notes=f"{vul_id} {row.get('cve_id')} patch {sha}",
                    )
                )
    if not units:
        raise SuiteError(
            "No Vul4J units parsed. Need CSV rows whose cwe_id is in the thesis set "
            f"and fetchable Java patches. errors={errors[:6]}"
        )
    return units


def mapping_notes(units: list[SeedUnit] | None = None) -> dict[str, Any]:
    notes: dict[str, Any] = {
        "gold": "vul4j_dataset.csv cwe_id; parent commit file = vulnerable, patch commit = fixed",
        "cwe_coverage_plan": {
            "CWE-89": "not present in CSV (thesis set)",
            "CWE-79": "present if fetch succeeds",
            "CWE-22": "present if fetch succeeds",
            "CWE-502": "present if fetch succeeds",
            "CWE-798": "not present in CSV",
            "CWE-327": "not present in CSV",
        },
        "license_note": LICENSE_NOTE,
    }
    if units is not None:
        notes["cwe_coverage"] = cwe_coverage(units)
        notes["per_cwe_n"] = label_counts(units)
    return notes
