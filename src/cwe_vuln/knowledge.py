"""Assignment 2: curated CWE knowledge layer and query interface.

Entries are a teaching subset derived from public CWE/MITRE facts, not an
official dump. No hybrid retrieval or reasoning agent lives here.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from cwe_vuln.dataset import repo_root

CWE_ID_RE = re.compile(r"^(?:CWE-)?(\d+)$", re.IGNORECASE)

SEED_CWE_IDS: tuple[str, ...] = (
    "CWE-89",
    "CWE-79",
    "CWE-22",
    "CWE-502",
    "CWE-798",
    "CWE-327",
)


def normalize_cwe_id(cwe_id: str) -> str:
    text = cwe_id.strip()
    match = CWE_ID_RE.match(text)
    if not match:
        raise ValueError(f"Invalid CWE id: {cwe_id!r}")
    return f"CWE-{int(match.group(1))}"


@dataclass(frozen=True)
class Mitigation:
    id: str
    title: str
    text: str


@dataclass(frozen=True)
class Relationships:
    parents: tuple[str, ...] = ()
    children: tuple[str, ...] = ()
    peers: tuple[str, ...] = ()

    def all_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys([*self.parents, *self.children, *self.peers]))


@dataclass(frozen=True)
class CWEEntry:
    id: str
    name: str
    description: str
    relationships: Relationships
    mitigations: tuple[Mitigation, ...]
    detection_notes: str = ""

    def searchable_text(self) -> str:
        parts = [self.id, self.name, self.description, self.detection_notes]
        for item in self.mitigations:
            parts.extend([item.title, item.text])
        return " ".join(parts).lower()


class KnowledgeError(RuntimeError):
    """Raised when the curated CWE store cannot be loaded or queried."""


@dataclass
class CWEKnowledgeBase:
    entries: dict[str, CWEEntry] = field(default_factory=dict)
    meta: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> CWEKnowledgeBase:
        store = path or default_knowledge_path()
        if not store.is_file():
            raise KnowledgeError(f"Missing CWE knowledge store: {store}")
        payload = json.loads(store.read_text(encoding="utf-8"))
        entries: dict[str, CWEEntry] = {}
        for raw in payload.get("entries", []):
            entry = _entry_from_payload(raw)
            if entry.id in entries:
                raise KnowledgeError(f"Duplicate CWE id in store: {entry.id}")
            entries[entry.id] = entry
        missing = [cwe_id for cwe_id in SEED_CWE_IDS if cwe_id not in entries]
        if missing:
            raise KnowledgeError(f"Knowledge store missing seed CWEs: {missing}")
        meta = {str(k): str(v) for k, v in payload.get("meta", {}).items()}
        return cls(entries=entries, meta=meta)

    def get(self, cwe_id: str) -> CWEEntry:
        key = normalize_cwe_id(cwe_id)
        try:
            return self.entries[key]
        except KeyError as exc:
            raise KnowledgeError(f"Unknown CWE id: {key}") from exc

    def search(self, text: str, *, limit: int = 10) -> list[tuple[CWEEntry, float]]:
        """Simple token-overlap search over names, descriptions, and mitigations."""
        query = [token for token in re.split(r"[^a-z0-9]+", text.lower()) if token]
        if not query:
            return []
        scored: list[tuple[CWEEntry, float]] = []
        for entry in self.entries.values():
            haystack = entry.searchable_text()
            hits = sum(1 for token in query if token in haystack)
            if hits:
                scored.append((entry, hits / len(query)))
        scored.sort(
            key=lambda item: (
                -item[1],
                item[0].id not in SEED_CWE_IDS,
                int(item[0].id.split("-")[1]),
            )
        )
        return scored[:limit]

    def relationships(self, cwe_id: str) -> Relationships:
        return self.get(cwe_id).relationships

    def mitigations(self, cwe_id: str) -> tuple[Mitigation, ...]:
        return self.get(cwe_id).mitigations

    def neighbors(self, cwe_id: str) -> list[CWEEntry]:
        rel = self.relationships(cwe_id)
        found: list[CWEEntry] = []
        for related_id in rel.all_ids():
            if related_id in self.entries:
                found.append(self.entries[related_id])
        return found

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.entries, key=lambda item: int(item.split("-")[1])))


def default_knowledge_path(root: Path | None = None) -> Path:
    return (root or repo_root()) / "data" / "cwe" / "knowledge.json"


def _entry_from_payload(raw: dict[str, object]) -> CWEEntry:
    rel_raw = raw.get("relationships") or {}
    if not isinstance(rel_raw, dict):
        raise KnowledgeError(f"relationships must be an object for {raw.get('id')}")
    mitigations_raw = raw.get("mitigations") or []
    if not isinstance(mitigations_raw, list):
        raise KnowledgeError(f"mitigations must be a list for {raw.get('id')}")
    mitigations = tuple(
        Mitigation(
            id=str(item["id"]),
            title=str(item["title"]),
            text=str(item["text"]),
        )
        for item in mitigations_raw
        if isinstance(item, dict)
    )
    return CWEEntry(
        id=normalize_cwe_id(str(raw["id"])),
        name=str(raw["name"]),
        description=str(raw["description"]),
        relationships=Relationships(
            parents=_id_tuple(rel_raw.get("parents")),
            children=_id_tuple(rel_raw.get("children")),
            peers=_id_tuple(rel_raw.get("peers")),
        ),
        mitigations=mitigations,
        detection_notes=str(raw.get("detection_notes") or ""),
    )


def _id_tuple(value: object) -> tuple[str, ...]:
    if not value:
        return ()
    if not isinstance(value, list):
        raise KnowledgeError("relationship lists must be arrays of CWE ids")
    return tuple(normalize_cwe_id(str(item)) for item in value)
