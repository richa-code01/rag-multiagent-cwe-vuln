"""Download the six scored benchmark slices at the pinned commits and drop nested git metadata.

Run once before committing ``data/benchmarks/``. Does not call an LLM.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from cwe_vuln.config import repo_root
from cwe_vuln.dataset.cvefixes import load_cvefixes_units
from cwe_vuln.dataset.findsecbugs import PINNED_COMMIT as FINDSEC_COMMIT
from cwe_vuln.dataset.findsecbugs import ensure_findsecbugs
from cwe_vuln.dataset.juliet import PINNED_COMMIT as JULIET_COMMIT
from cwe_vuln.dataset.juliet import ensure_juliet
from cwe_vuln.dataset.owasp import PINNED_COMMIT as OWASP_COMMIT
from cwe_vuln.dataset.owasp import ensure_owasp
from cwe_vuln.dataset.securibench import PINNED_COMMIT as SECURI_COMMIT
from cwe_vuln.dataset.securibench import ensure_securibench
from cwe_vuln.dataset.vul4j import PINNED_COMMIT as VUL4J_COMMIT
from cwe_vuln.dataset.vul4j import ensure_vul4j, load_vul4j_units


def _strip_git(root: Path) -> None:
    for git_dir in root.rglob(".git"):
        if git_dir.is_dir():
            shutil.rmtree(git_dir)


def _largest_file(root: Path) -> tuple[int, Path | None]:
    biggest = 0
    path: Path | None = None
    if not root.exists():
        return 0, None
    for item in root.rglob("*"):
        if item.is_file() and item.stat().st_size > biggest:
            biggest = item.stat().st_size
            path = item
    return biggest, path


def main() -> int:
    root = repo_root()
    benchmarks = root / "data" / "benchmarks"
    print("juliet", flush=True)
    juliet = ensure_juliet(root)
    print(" ", juliet.sha256_or_commit, flush=True)
    print("owasp", flush=True)
    print(" ", ensure_owasp(root)["sha256_or_commit"], flush=True)
    print("securibench", flush=True)
    print(" ", ensure_securibench(root)["sha256_or_commit"], flush=True)
    print("find-sec-bugs", flush=True)
    print(" ", ensure_findsecbugs(root)["sha256_or_commit"], flush=True)
    print("vul4j metadata", flush=True)
    print(" ", ensure_vul4j(root)["sha256_or_commit"], flush=True)
    print("vul4j java files", flush=True)
    vul_units = load_vul4j_units(root, fetch_patches=True)
    print(" ", len(vul_units), "units", flush=True)
    print("cvefixes java files", flush=True)
    cve_units = load_cvefixes_units(root, fetch_patches=True)
    print(" ", len(cve_units), "units", flush=True)

    expected = {
        "juliet": (juliet.sha256_or_commit, JULIET_COMMIT),
        "owasp": (ensure_owasp(root)["sha256_or_commit"], OWASP_COMMIT),
        "securibench": (ensure_securibench(root)["sha256_or_commit"], SECURI_COMMIT),
        "find-sec-bugs": (ensure_findsecbugs(root)["sha256_or_commit"], FINDSEC_COMMIT),
        "vul4j": (ensure_vul4j(root)["sha256_or_commit"], VUL4J_COMMIT),
    }
    failed = False
    for name, (got, want) in expected.items():
        if got != want and not str(got).startswith(want) and not want.startswith(str(got)):
            print(f"PIN MISMATCH {name}: got {got} want {want}", flush=True)
            failed = True
    _strip_git(benchmarks)
    for name in (
        "juliet-java",
        "owasp-benchmark",
        "securibench-micro",
        "find-sec-bugs",
        "vul4j",
        "vul4j-files",
        "cvefixes-files",
    ):
        size, big = _largest_file(benchmarks / name)
        print(f"largest {name}: {size} {big}", flush=True)
        if size > 95 * 1024 * 1024:
            print(f"FILE TOO LARGE {name}", flush=True)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
