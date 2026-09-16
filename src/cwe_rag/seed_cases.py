"""Labeled seed snippets for offline evaluation.

Precision / recall / F1 of 1.0 on this set is seed-only. It is not a
Big-Vul, Juliet, or production benchmark result.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SeedCase:
    case_id: str
    language: str
    code: str
    vulnerable: bool
    cwe_id: str | None


SEED_CASES: tuple[SeedCase, ...] = (
    SeedCase(
        case_id="sqli-concat",
        language="python",
        code='cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
        vulnerable=True,
        cwe_id="CWE-89",
    ),
    SeedCase(
        case_id="sqli-parameterized",
        language="python",
        code='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        vulnerable=False,
        cwe_id=None,
    ),
    SeedCase(
        case_id="xss-innerhtml",
        language="javascript",
        code="el.innerHTML = req.query.comment",
        vulnerable=True,
        cwe_id="CWE-79",
    ),
    SeedCase(
        case_id="xss-textcontent",
        language="javascript",
        code="el.textContent = req.query.comment",
        vulnerable=False,
        cwe_id=None,
    ),
    SeedCase(
        case_id="cmdi-os-system",
        language="python",
        code="os.system('ping ' + host)",
        vulnerable=True,
        cwe_id="CWE-78",
    ),
    SeedCase(
        case_id="cmdi-argv-list",
        language="python",
        code="subprocess.run(['ping', '-c', '1', host], check=False)",
        vulnerable=False,
        cwe_id=None,
    ),
    SeedCase(
        case_id="path-open-user",
        language="python",
        code="open(os.path.join(base, filename)).read()",
        vulnerable=True,
        cwe_id="CWE-22",
    ),
    SeedCase(
        case_id="path-jail",
        language="python",
        code=(
            "path = (base / name).resolve()\n"
            "if base.resolve() not in path.parents and path != base.resolve():\n"
            "    raise ValueError('escape')\n"
            "path.read_text()\n"
        ),
        vulnerable=False,
        cwe_id=None,
    ),
)
