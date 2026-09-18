"""Guard rails: the Groq key must never land in git; raw LLM captures stay local."""

import re
import subprocess
from pathlib import Path

from cwe_vuln.config import repo_root

_KEY = re.compile(r"gsk_[A-Za-z0-9]{20,}")


def _tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_root(),
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [line for line in out.stdout.splitlines() if line.strip()]


def test_no_groq_key_in_tracked_files() -> None:
    offenders: list[str] = []
    for rel in _tracked_files():
        path = repo_root() / rel
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _KEY.search(text):
            offenders.append(rel)
    assert offenders == [], f"Groq key material in tracked files: {offenders}"


def test_env_and_raw_llm_are_gitignored() -> None:
    gitignore = (repo_root() / ".gitignore").read_text(encoding="utf-8")
    assert "\n.env\n" in f"\n{gitignore}"
    assert "raw_llm/" in gitignore


def test_env_file_is_not_tracked() -> None:
    assert ".env" not in _tracked_files()
