"""Seed CWE knowledge used by the research slice.

Entries are short, original summaries of public CWE identities — enough
for lexical retrieval in tests. This is not a dump of MITRE's corpus.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CweRecord:
    cwe_id: str
    name: str
    summary: str
    keywords: tuple[str, ...]


SEED_CWES: tuple[CweRecord, ...] = (
    CweRecord(
        cwe_id="CWE-89",
        name="SQL Injection",
        summary=(
            "User-controlled strings are concatenated into SQL statements so an "
            "attacker can change the query. Parameterized queries or bound "
            "placeholders are the usual fix."
        ),
        keywords=(
            "sql",
            "query",
            "execute",
            "select",
            "insert",
            "cursor",
            "database",
            "injection",
        ),
    ),
    CweRecord(
        cwe_id="CWE-79",
        name="Cross-site Scripting",
        summary=(
            "Untrusted input is written into HTML without encoding, allowing "
            "script injection in another user's browser. Escape output or use "
            "text-only DOM APIs."
        ),
        keywords=(
            "html",
            "xss",
            "innerhtml",
            "script",
            "template",
            "browser",
            "dom",
        ),
    ),
    CweRecord(
        cwe_id="CWE-78",
        name="OS Command Injection",
        summary=(
            "Application code passes unsanitized user data to a shell. Use "
            "argument lists without shell=True, or drop to a library API."
        ),
        keywords=(
            "command",
            "shell",
            "os.system",
            "subprocess",
            "popen",
            "bash",
        ),
    ),
    CweRecord(
        cwe_id="CWE-22",
        name="Path Traversal",
        summary=(
            "User-supplied file paths containing '..' escape an intended "
            "directory. Resolve the path and check it stays under a jail."
        ),
        keywords=(
            "path",
            "traversal",
            "filename",
            "open",
            "directory",
            "dotdot",
        ),
    ),
)


def by_id() -> dict[str, CweRecord]:
    return {record.cwe_id: record for record in SEED_CWES}
