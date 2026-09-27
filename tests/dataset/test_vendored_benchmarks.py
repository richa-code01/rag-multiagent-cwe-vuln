"""The scored benchmark slices are vendored at the commits the thesis measured."""

from __future__ import annotations

import json
from pathlib import Path

from cwe_vuln.config import repo_root
from cwe_vuln.dataset.findsecbugs import PINNED_COMMIT as FINDSEC_COMMIT
from cwe_vuln.dataset.juliet import PINNED_COMMIT as JULIET_COMMIT
from cwe_vuln.dataset.owasp import PINNED_COMMIT as OWASP_COMMIT
from cwe_vuln.dataset.securibench import PINNED_COMMIT as SECURI_COMMIT
from cwe_vuln.dataset.vul4j import PINNED_COMMIT as VUL4J_COMMIT

ROOT = repo_root() / "data" / "benchmarks"


def _commit(name: str) -> str:
    payload = json.loads((ROOT / name).read_text(encoding="utf-8"))
    return str(payload["sha256_or_commit"])


def test_vendored_roots_match_pinned_commits() -> None:
    assert (ROOT / "juliet-java" / "src" / "testcases" / "CWE89_SQL_Injection").is_dir()
    assert (ROOT / "owasp-benchmark" / "expectedresults-1.2.csv").is_file()
    assert (ROOT / "securibench-micro" / "src" / "securibench" / "micro").is_dir()
    assert (ROOT / "find-sec-bugs").is_dir()
    assert (ROOT / "vul4j" / "dataset" / "vul4j_dataset.csv").is_file()
    assert any((ROOT / "vul4j-files").rglob("*.java"))
    assert any((ROOT / "cvefixes-files").rglob("*.java"))
    assert not any(ROOT.rglob(".git"))
    assert _commit("juliet_provenance.json") == JULIET_COMMIT
    assert _commit("owasp_benchmark_provenance.json") == OWASP_COMMIT
    assert _commit("securibench_micro_provenance.json") == SECURI_COMMIT
    assert _commit("find_sec_bugs_provenance.json") == FINDSEC_COMMIT
    assert _commit("vul4j_provenance.json") == VUL4J_COMMIT
    notices = (ROOT / "NOTICES.md").read_text(encoding="utf-8")
    assert JULIET_COMMIT in notices
    for path in ROOT.rglob("*"):
        if path.is_file():
            assert path.stat().st_size < 95 * 1024 * 1024
    assert Path(ROOT / "juliet-java").exists()
