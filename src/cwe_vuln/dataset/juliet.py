"""Map NIST Juliet Java testcases onto SeedUnit without mixing good/bad gold.

Juliet Java v1.3 often collocates bad() and good*() in one file. Whole-file scoring
would leak both labels. This adapter emits method-level or filename-level units.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zipfile import ZipFile

from cwe_vuln.config import repo_root
from cwe_vuln.dataset.seed import SeedUnit

NIST_SUITE_PAGE = "https://samate.nist.gov/SARD/test-suites/111"
NIST_ZIP_URL = (
    "https://samate.nist.gov/SARD/downloads/test-suites/"
    "2017-10-01-juliet-test-suite-for-java-v1-3.zip"
)
NIST_SHA256 = "d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60"
JULIET_VERSION = "1.3"
GITHUB_REPO = "https://github.com/find-sec-bugs/juliet-test-suite.git"
SAMPLE_SEED = 13
DEFAULT_PER_CWE = 20
# Live Groq sample uses these gold ids only; remaining ingested ids are SAST-only.
LLM_SAMPLE_CWES: tuple[str, ...] = (
    "CWE-89",
    "CWE-80",
    "CWE-23",
    "CWE-327",
    "CWE-328",
    "CWE-259",
)

# Thesis primaries that have a Juliet Java 1.3 folder with the same CWE number.
PRIMARY_PRESENT = (89, 327)
# Thesis primaries with no Juliet Java 1.3 folder (do not invent units).
PRIMARY_MISSING = (79, 22, 502, 798)

# Folders we ingest. Nearby ids keep their Juliet CWE number.
INGEST_FOLDERS: tuple[tuple[int, str, str], ...] = (
    (89, "CWE89_SQL_Injection", "primary"),
    (80, "CWE80_XSS", "nearby_missing_CWE79"),
    (81, "CWE81_XSS_Error_Message", "nearby_missing_CWE79"),
    (83, "CWE83_XSS_Attribute", "nearby_missing_CWE79"),
    (23, "CWE23_Relative_Path_Traversal", "nearby_missing_CWE22"),
    (36, "CWE36_Absolute_Path_Traversal", "nearby_missing_CWE22"),
    (327, "CWE327_Use_Broken_Crypto", "primary"),
    (328, "CWE328_Reversible_One_Way_Hash", "nearby_CWE327_not_relabeled"),
    (259, "CWE259_Hard_Coded_Password", "nearby_missing_CWE798"),
    (321, "CWE321_Hard_Coded_Cryptographic_Key", "nearby_missing_CWE798"),
)

SKIP_FILE_NAMES = {"Main.java", "ServletMain.java"}
SKIP_NAME_PARTS = ("_base.java", "_helper.java")
# Juliet flow variants: CWE259_...__driverManager_81a.java calls 81b which holds the sink.
# Pair scoring on the `a` file hides the sink from the LLM. Exclude from the pair pool.
MULTI_FILE_STEM = re.compile(r"_\d{2}[a-z]$")
METHOD_SIG = re.compile(
    r"(?:public|private|protected)\s+(?:static\s+)?void\s+(bad|good[A-Za-z0-9]*)\s*\(",
    re.MULTILINE,
)
CWE_DIR = re.compile(r"(?:^|/)CWE(\d+)_")
FILE_BAD = re.compile(r"_bad\.java$", re.IGNORECASE)
FILE_GOOD = re.compile(r"_good[A-Za-z0-9]*\.java$", re.IGNORECASE)
DISPATCHER_BODY = re.compile(r"^\s*good[A-Za-z0-9]*\s*\(\s*\)\s*;\s*$", re.MULTILINE)


class JulietError(RuntimeError):
    """Raised when the Juliet tree cannot be located or parsed."""


@dataclass(frozen=True)
class JulietProvenance:
    version: str
    source_url: str
    downloaded_at: str
    method: str
    sha256_or_commit: str
    notes: str

    def as_dict(self) -> dict[str, str]:
        return {
            "juliet_version": self.version,
            "source_url": self.source_url,
            "downloaded_at": self.downloaded_at,
            "method": self.method,
            "sha256_or_commit": self.sha256_or_commit,
            "nist_suite_page": NIST_SUITE_PAGE,
            "notes": self.notes,
        }


def benchmarks_dir(root: Path | None = None) -> Path:
    return (root or repo_root()) / "data" / "benchmarks"


def juliet_root(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "juliet-java"


def provenance_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "juliet_provenance.json"


def sample_manifest_path(root: Path | None = None) -> Path:
    return benchmarks_dir(root) / "juliet_llm_sample.json"


def mapping_notes() -> dict[str, Any]:
    return {
        "thesis_cwes": ["CWE-89", "CWE-79", "CWE-22", "CWE-502", "CWE-798", "CWE-327"],
        "primary_present": [f"CWE-{n}" for n in PRIMARY_PRESENT],
        "primary_missing_in_juliet_java_1_3": [f"CWE-{n}" for n in PRIMARY_MISSING],
        "ingest_folders": [
            {"cwe_id": f"CWE-{cwe}", "folder": folder, "role": role}
            for cwe, folder, role in INGEST_FOLDERS
        ],
        "llm_sample_cwes": list(LLM_SAMPLE_CWES),
        "sast_only_ingested_cwes": ["CWE-81", "CWE-83", "CWE-36", "CWE-321"],
        "cwe502": "no Juliet Java 1.3 folder; not evaluated",
        "retrieval_at_juliet": (
            "nearby gold ids (80, 23, 259, 328, …) are in the MITRE XML subset; "
            "retrieval@sample is computed on the Juliet pair sample"
        ),
        "multi_file_exclusion": (
            "Juliet _NNa/_NNb flow variants are ingested for SAST but excluded from "
            "the C2 pair pool: the `a` file often only forwards data to a `b` helper "
            "that holds the sink, so the LLM never sees the vulnerable line."
        ),
    }


def is_multi_file_juliet_stem(stem: str) -> bool:
    """True for Juliet flow-variant stems such as ``..._81a`` / ``..._68b``."""
    return bool(MULTI_FILE_STEM.search(stem))


def is_multi_file_juliet_unit(unit: SeedUnit) -> bool:
    """True when the unit comes from a multi-file (_NNa/_NNb) Juliet variant."""
    if is_multi_file_juliet_stem(Path(unit.path).stem):
        return True
    stripped = re.sub(r"__(method_|file_)?(bad|good[A-Za-z0-9]*)$", "", unit.unit_id)
    return is_multi_file_juliet_stem(stripped)


def ensure_juliet(root: Path | None = None) -> JulietProvenance:
    """Download Juliet Java if needed. NIST zip first, GitHub sparse clone on failure."""
    base = root or repo_root()
    dest = juliet_root(base)
    existing = _existing_tree(dest)
    if existing is not None:
        return existing
    dest.parent.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    try:
        prov = _download_nist_zip(base, dest)
        _write_provenance(base, prov)
        return prov
    except Exception as exc:
        errors.append(f"nist_zip_failed: {exc}")
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
    try:
        prov = _clone_github(dest)
        prov = JulietProvenance(
            version=prov.version,
            source_url=prov.source_url,
            downloaded_at=prov.downloaded_at,
            method=prov.method,
            sha256_or_commit=prov.sha256_or_commit,
            notes=prov.notes + " Prior NIST attempt: " + "; ".join(errors),
        )
        _write_provenance(base, prov)
        return prov
    except Exception as exc:
        errors.append(f"github_clone_failed: {exc}")
        raise JulietError(
            "Juliet Java download failed. " + " | ".join(errors)
        ) from exc


def load_juliet_units(
    root: Path | None = None,
    *,
    tree: Path | None = None,
    require_download: bool = False,
) -> list[SeedUnit]:
    """Parse mapped Juliet Java files into SeedUnits."""
    base = root or repo_root()
    if require_download:
        ensure_juliet(base)
    src = tree if tree is not None else _testcases_dir(juliet_root(base))
    if src is None or not src.is_dir():
        raise JulietError(
            f"Juliet testcases not found under {juliet_root(base)}. "
            "Run ensure_juliet() or pass tree= to a local checkout."
        )
    units: list[SeedUnit] = []
    for cwe_num, folder, role in INGEST_FOLDERS:
        folder_path = src / folder
        if not folder_path.is_dir():
            continue
        for java in sorted(folder_path.rglob("*.java")):
            units.extend(_units_from_file(java, cwe_num, role, base))
    if not units:
        raise JulietError(f"No Juliet units parsed from {src}")
    return units


def stratified_sample(
    units: list[SeedUnit],
    *,
    per_cwe: int = DEFAULT_PER_CWE,
    seed: int = SAMPLE_SEED,
    cwe_ids: tuple[str, ...] | None = None,
) -> list[SeedUnit]:
    """Deterministic half-good / half-bad sample per Juliet gold CWE id."""
    pool = [unit for unit in units if cwe_ids is None or unit.cwe_id in cwe_ids]
    rng = random.Random(seed)
    grouped: dict[str, dict[str, list[SeedUnit]]] = {}
    for unit in pool:
        grouped.setdefault(unit.cwe_id, {"vulnerable": [], "not_vulnerable": []})
        grouped[unit.cwe_id][unit.label].append(unit)
    sampled: list[SeedUnit] = []
    half = max(1, per_cwe // 2)
    for cwe_id in sorted(grouped):
        for label in ("vulnerable", "not_vulnerable"):
            pool = list(grouped[cwe_id][label])
            rng.shuffle(pool)
            sampled.extend(pool[:half])
    sampled.sort(key=lambda item: item.unit_id)
    return sampled


def write_sample_manifest(
    units: list[SeedUnit],
    path: Path | None = None,
    *,
    per_cwe: int = DEFAULT_PER_CWE,
    seed: int = SAMPLE_SEED,
    provenance: dict[str, Any] | None = None,
) -> Path:
    dest = path or sample_manifest_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, dict[str, int]] = {}
    for unit in units:
        bucket = counts.setdefault(unit.cwe_id, {"vulnerable": 0, "not_vulnerable": 0, "n": 0})
        bucket[unit.label] += 1
        bucket["n"] += 1
    payload = {
        "seed": seed,
        "per_cwe_target": per_cwe,
        "n_units": len(units),
        "juliet_version": JULIET_VERSION,
        "mapping": mapping_notes(),
        "provenance": provenance,
        "per_cwe_counts": counts,
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
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return dest


def load_sample_units(
    units: list[SeedUnit],
    manifest: Path | None = None,
) -> list[SeedUnit]:
    path = manifest or sample_manifest_path()
    if not path.is_file():
        raise JulietError(f"Missing LLM sample manifest: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    wanted = list(payload["unit_ids"])
    index = {unit.unit_id: unit for unit in units}
    missing = [uid for uid in wanted if uid not in index]
    if missing:
        raise JulietError(f"Sample ids not in loaded Juliet units: {missing[:8]}")
    return [index[uid] for uid in wanted]


def _write_provenance(root: Path, prov: JulietProvenance) -> None:
    path = provenance_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(prov.as_dict(), indent=2) + "\n", encoding="utf-8")


def _existing_tree(dest: Path) -> JulietProvenance | None:
    if _testcases_dir(dest) is None:
        return None
    prov_file = dest.parent / "juliet_provenance.json"
    if prov_file.is_file():
        payload = json.loads(prov_file.read_text(encoding="utf-8"))
        return JulietProvenance(
            version=str(payload.get("juliet_version", JULIET_VERSION)),
            source_url=str(payload.get("source_url", "")),
            downloaded_at=str(payload.get("downloaded_at", "")),
            method=str(payload.get("method", "cached")),
            sha256_or_commit=str(payload.get("sha256_or_commit", "")),
            notes=str(payload.get("notes", "reused existing tree")),
        )
    return JulietProvenance(
        version=JULIET_VERSION,
        source_url="local",
        downloaded_at="",
        method="cached",
        sha256_or_commit="",
        notes="existing juliet-java tree, no provenance file",
    )


def _testcases_dir(dest: Path) -> Path | None:
    if not dest.exists():
        return None
    candidates = [
        dest / "src" / "testcases",
        dest / "Java" / "src" / "testcases",
        dest / "C" / "testcases",
    ]
    for path in dest.glob("**/src/testcases"):
        candidates.append(path)
    seen: set[Path] = set()
    for path in candidates:
        resolved = path.resolve() if path.exists() else path
        if resolved in seen:
            continue
        seen.add(resolved)
        if path.is_dir() and any(path.glob("CWE89_SQL_Injection")):
            return path
        if path.is_dir() and any(child.name.startswith("CWE") for child in path.iterdir()):
            return path
    return None


def _download_nist_zip(root: Path, dest: Path) -> JulietProvenance:
    downloads = benchmarks_dir(root) / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    zip_path = downloads / "juliet-java-1.3.zip"
    if not zip_path.is_file():
        urllib.request.urlretrieve(NIST_ZIP_URL, zip_path)
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    extract_to = dest.parent / "juliet-extract"
    if extract_to.exists():
        shutil.rmtree(extract_to)
    extract_to.mkdir(parents=True)
    with ZipFile(zip_path) as archive:
        archive.extractall(extract_to)
    testcases = _testcases_dir(extract_to)
    if testcases is None:
        raise JulietError(f"NIST zip extracted but no src/testcases under {extract_to}")
    if dest.exists():
        shutil.rmtree(dest)
    # Keep a compact tree: copy only mapped CWE folders + support if present.
    dest.mkdir(parents=True)
    src_root = testcases.parent  # .../src
    target_src = dest / "src" / "testcases"
    target_src.mkdir(parents=True)
    for _cwe, folder, _role in INGEST_FOLDERS:
        src_folder = testcases / folder
        if src_folder.is_dir():
            shutil.copytree(src_folder, target_src / folder)
    support = src_root / "testcasesupport"
    if support.is_dir():
        shutil.copytree(support, dest / "src" / "testcasesupport")
    shutil.rmtree(extract_to, ignore_errors=True)
    note = "NIST zip SHA-256 matched catalog." if digest == NIST_SHA256 else f"NIST zip SHA-256 {digest} (catalog {NIST_SHA256})."
    return JulietProvenance(
        version=JULIET_VERSION,
        source_url=NIST_ZIP_URL,
        downloaded_at=_utc_now(),
        method="nist_zip",
        sha256_or_commit=digest,
        notes=note,
    )


def _clone_github(dest: Path) -> JulietProvenance:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    folders = [f"src/testcases/{name}" for _cwe, name, _role in INGEST_FOLDERS]
    folders.append("src/testcasesupport")
    cmd = [
        "git",
        "clone",
        "--filter=blob:none",
        "--sparse",
        "--depth",
        "1",
        GITHUB_REPO,
        str(dest),
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    sparse = ["git", "-C", str(dest), "sparse-checkout", "set", *folders]
    subprocess.run(sparse, check=True, capture_output=True, text=True)
    rev = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    commit = rev.stdout.strip()
    return JulietProvenance(
        version=JULIET_VERSION,
        source_url=GITHUB_REPO,
        downloaded_at=_utc_now(),
        method="github_sparse_clone",
        sha256_or_commit=commit,
        notes="NIST zip failed or was blocked; used find-sec-bugs Juliet Java 1.3 mirror.",
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _units_from_file(path: Path, cwe_num: int, role: str, repo: Path) -> list[SeedUnit]:
    name = path.name
    if name in SKIP_FILE_NAMES or any(part in name for part in SKIP_NAME_PARTS):
        return []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = _relpath(path, repo)
    cwe_id = f"CWE-{cwe_num}"
    if FILE_BAD.search(name):
        return [_unit(path, rel, cwe_id, role, "vulnerable", source, "file_bad")]
    if FILE_GOOD.search(name):
        return [_unit(path, rel, cwe_id, role, "not_vulnerable", source, "file_good")]
    return _units_from_methods(path, rel, cwe_id, role, source)


def _units_from_methods(
    path: Path,
    rel: str,
    cwe_id: str,
    role: str,
    source: str,
) -> list[SeedUnit]:
    header = _import_header(source)
    units: list[SeedUnit] = []
    for method_name, body in _extract_methods(source):
        if method_name == "good" and _is_dispatcher(body):
            continue
        if method_name == "bad":
            label = "vulnerable"
        elif method_name.startswith("good"):
            label = "not_vulnerable"
        else:
            continue
        wrapped = f"{header}\npublic class JulietExtracted {{\n{body}\n}}\n"
        units.append(
            _unit(path, rel, cwe_id, role, label, wrapped, f"method_{method_name}")
        )
    return units


def _unit(
    path: Path,
    rel: str,
    cwe_id: str,
    role: str,
    label: str,
    source: str,
    kind: str,
) -> SeedUnit:
    parent = path.parent.name
    stem = path.stem
    unit_id = f"juliet_{parent}_{stem}__{kind}"
    return SeedUnit(
        unit_id=unit_id,
        cwe_id=cwe_id,
        path=rel,
        split="juliet",
        label=label,  # type: ignore[arg-type]
        notes=f"juliet {kind} role={role}",
        source=source,
        trap_type="juliet",
        corpus="juliet",
    )


def _relpath(path: Path, repo: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo.resolve()))
    except ValueError:
        return str(path)


def _import_header(source: str) -> str:
    lines = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("package ") or stripped.startswith("import "):
            lines.append(line)
        if stripped.startswith("public class") or stripped.startswith("public abstract class"):
            break
    return "\n".join(lines)


def _extract_methods(source: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for match in METHOD_SIG.finditer(source):
        name = match.group(1)
        brace_at = source.find("{", match.end())
        if brace_at < 0:
            continue
        end = _matching_brace(source, brace_at)
        if end < 0:
            continue
        start = match.start()
        found.append((name, source[start:end]))
    return found


def _matching_brace(source: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    n = len(source)
    in_str = False
    in_char = False
    in_line = False
    in_block = False
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if in_line:
            if ch == "\n":
                in_line = False
            i += 1
            continue
        if in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                i += 2
                continue
            i += 1
            continue
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if in_char:
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                in_char = False
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block = True
            i += 2
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch == "'":
            in_char = True
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _is_dispatcher(body: str) -> bool:
    inner = body
    start = inner.find("{")
    end = inner.rfind("}")
    if start < 0 or end < 0:
        return False
    chunk = inner[start + 1 : end]
    code = re.sub(r"/\*.*?\*/", "", chunk, flags=re.S)
    code = re.sub(r"//.*?$", "", code, flags=re.M)
    statements = [line.strip() for line in code.splitlines() if line.strip()]
    if not statements:
        return True
    return all(DISPATCHER_BODY.match(line) for line in statements)
