"""Validate reasoning-output JSON against the Assignment 4 schema."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cwe_vuln.schema import validate_output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate reasoning-output JSON against the Assignment 4 schema.")
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args(argv)
    failed = 0
    for path in args.paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        errors = validate_output(payload)
        if errors:
            failed += 1
            print(f"INVALID {path}")
            for item in errors:
                print(f"  {item}")
        else:
            print(f"VALID {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
