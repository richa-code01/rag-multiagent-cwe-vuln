"""Sample CWE knowledge queries (Assignment 2). No retrieval agent here."""

from __future__ import annotations

import argparse
import json

from cwe_vuln.knowledge import CWEKnowledgeBase


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Query the curated CWE knowledge layer.")
    sub = parser.add_subparsers(dest="command", required=True)

    get_p = sub.add_parser("get", help="Lookup one CWE id")
    get_p.add_argument("cwe_id")

    search_p = sub.add_parser("search", help="Token search over names and descriptions")
    search_p.add_argument("text")
    search_p.add_argument("--limit", type=int, default=5)

    rel_p = sub.add_parser("relationships", help="Parents / children / peers")
    rel_p.add_argument("cwe_id")

    mit_p = sub.add_parser("mitigations", help="Mitigations for one CWE")
    mit_p.add_argument("cwe_id")

    sub.add_parser("demo", help="Run the documented sample queries")

    args = parser.parse_args(argv)
    kb = CWEKnowledgeBase.load()

    if args.command == "get":
        entry = kb.get(args.cwe_id)
        print(json.dumps(_entry_dict(entry), indent=2))
        return 0
    if args.command == "search":
        hits = kb.search(args.text, limit=args.limit)
        payload = [{"id": entry.id, "name": entry.name, "score": round(score, 3)} for entry, score in hits]
        print(json.dumps(payload, indent=2))
        return 0
    if args.command == "relationships":
        rel = kb.relationships(args.cwe_id)
        print(
            json.dumps(
                {
                    "cwe_id": kb.get(args.cwe_id).id,
                    "parents": list(rel.parents),
                    "children": list(rel.children),
                    "peers": list(rel.peers),
                    "resolved_neighbors": [entry.id for entry in kb.neighbors(args.cwe_id)],
                },
                indent=2,
            )
        )
        return 0
    if args.command == "mitigations":
        items = kb.mitigations(args.cwe_id)
        print(
            json.dumps(
                [{"id": item.id, "title": item.title, "text": item.text} for item in items],
                indent=2,
            )
        )
        return 0
    if args.command == "demo":
        _demo(kb)
        return 0
    parser.error(f"unknown command {args.command}")
    return 2


def _demo(kb: CWEKnowledgeBase) -> None:
    print("== get CWE-89 ==")
    entry = kb.get("CWE-89")
    print(f"{entry.id}: {entry.name}")
    print(entry.description)
    print()
    print("== search 'cross site scripting' ==")
    for hit, score in kb.search("cross site scripting", limit=3):
        print(f"  {hit.id} ({score:.2f}) {hit.name}")
    print()
    print("== relationships CWE-798 ==")
    rel = kb.relationships("CWE-798")
    print(f"  parents={list(rel.parents)} children={list(rel.children)} peers={list(rel.peers)}")
    print("== mitigations CWE-22 ==")
    for item in kb.mitigations("CWE-22"):
        print(f"  - {item.title}: {item.text}")


def _entry_dict(entry) -> dict[str, object]:
    return {
        "id": entry.id,
        "name": entry.name,
        "description": entry.description,
        "relationships": {
            "parents": list(entry.relationships.parents),
            "children": list(entry.relationships.children),
            "peers": list(entry.relationships.peers),
        },
        "mitigations": [
            {"id": item.id, "title": item.title, "text": item.text} for item in entry.mitigations
        ],
        "detection_notes": entry.detection_notes,
    }


if __name__ == "__main__":
    raise SystemExit(main())
