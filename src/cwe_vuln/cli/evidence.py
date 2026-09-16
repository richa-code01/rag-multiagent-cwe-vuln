"""Extract SAST evidence objects from seed Java units."""

from __future__ import annotations

import argparse
import json

from cwe_vuln.dataset import load_seed
from cwe_vuln.sast import extract_evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract SAST evidence objects from seed Java units.")
    parser.add_argument("--unit-id", dest="unit_id", default=None)
    args = parser.parse_args(argv)
    units = load_seed()
    if args.unit_id:
        units = [unit for unit in units if unit.unit_id == args.unit_id]
        if not units:
            print(f"unknown unit_id {args.unit_id}")
            return 1
    payload = [
        {"unit_id": unit.unit_id, "evidence": [item.to_dict() for item in extract_evidence(unit)]}
        for unit in units
    ]
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
