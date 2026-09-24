"""Build the CWE knowledge store from the official MITRE CWE XML catalog.

Replaces the hand-written 20-entry teaching file with a parsed subset of the
official catalog (cwec_v*.xml). The subset covers the thesis CWE families plus
their view-1000 relationship neighborhood; it is still a subset, not the full
catalog. The raw XML stays in the gitignored downloads cache; the parsed JSON
is committed with the catalog version/date recorded in meta.
"""

from __future__ import annotations

import json
import re
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree

from cwe_vuln.config import repo_root
from cwe_vuln.knowledge.store import normalize_cwe_id

CWE_XML_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
_NS = "{http://cwe.mitre.org/cwe-7}"
_RELATION_VIEWS = ("1000", "699")  # Research Concepts, then Development Concepts

# Thesis families: the six seed CWEs plus the nearby/public-suite ids we ingest.
SEED_IDS: tuple[str, ...] = (
    "CWE-89", "CWE-79", "CWE-22", "CWE-502", "CWE-798", "CWE-327",
    "CWE-80", "CWE-81", "CWE-83", "CWE-23", "CWE-36",
    "CWE-259", "CWE-321", "CWE-328",
)


@dataclass(frozen=True)
class RawWeakness:
    """One parsed <Weakness> element, text fields already tag-stripped."""

    cwe_id: str
    name: str
    abstraction: str
    status: str
    description: str
    extended_description: str = ""
    relations: tuple[tuple[str, str], ...] = ()  # (nature, other CWE id)
    consequences: tuple[str, ...] = ()
    mitigations: tuple[tuple[str, str], ...] = ()  # (phases, description)
    detection_methods: tuple[str, ...] = ()


@dataclass
class _Catalog:
    version: str
    date: str
    weaknesses: dict[str, RawWeakness] = field(default_factory=dict)


def downloads_dir(root: Path | None = None) -> Path:
    path = (root or repo_root()) / "data" / "benchmarks" / "downloads"
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_cwe_xml(root: Path | None = None) -> Path:
    """Download + extract the CWE XML zip once; reuse the extracted file."""
    base = downloads_dir(root)
    existing = sorted(base.glob("cwec_v*.xml"))
    if existing:
        return existing[0]
    zip_path = base / "cwec_latest.xml.zip"
    if not zip_path.is_file():
        urllib.request.urlretrieve(CWE_XML_ZIP_URL, zip_path)
    with zipfile.ZipFile(zip_path) as archive:
        archive.extractall(base)
    extracted = sorted(base.glob("cwec_v*.xml"))
    if not extracted:
        raise RuntimeError(f"CWE XML zip extracted but no cwec_v*.xml under {base}")
    return extracted[0]


def parse_catalog(xml_path: Path) -> _Catalog:
    root = ElementTree.parse(xml_path).getroot()
    catalog = _Catalog(version=root.get("Version", ""), date=root.get("Date", ""))
    for weakness in root.iter(f"{_NS}Weakness"):
        cwe_id = f"CWE-{weakness.get('ID', '').strip()}"
        catalog.weaknesses[cwe_id] = RawWeakness(
            cwe_id=cwe_id,
            name=(weakness.get("Name") or "").strip(),
            abstraction=weakness.get("Abstraction", ""),
            status=weakness.get("Status", ""),
            description=_text(weakness.find(f"{_NS}Description")),
            extended_description=_text(weakness.find(f"{_NS}Extended_Description")),
            relations=_relations(weakness),
            consequences=_consequences(weakness),
            mitigations=_mitigations(weakness),
            detection_methods=_detection_methods(weakness),
        )
    return catalog


def expand_ids(catalog: _Catalog, seed_ids: tuple[str, ...] = SEED_IDS, hops: int = 1) -> list[str]:
    """BFS over view-1000/699 relationships from the seed ids."""
    seen = set(seed_ids)
    frontier = set(seed_ids)
    for _ in range(hops):
        nxt: set[str] = set()
        for cwe_id in frontier:
            weakness = catalog.weaknesses.get(cwe_id)
            if weakness is None:
                continue
            for _nature, other in weakness.relations:
                if other not in seen and other in catalog.weaknesses:
                    nxt.add(other)
        seen |= nxt
        frontier = nxt
    return sorted(seen, key=lambda item: int(item.split("-")[1]))


def build_knowledge_payload(catalog: _Catalog, ids: list[str]) -> dict:
    entries = []
    for cwe_id in ids:
        weakness = catalog.weaknesses.get(cwe_id)
        if weakness is None:
            continue
        parents, children, peers = _split_relations(weakness, catalog)
        entries.append(
            {
                "id": normalize_cwe_id(cwe_id),
                "name": weakness.name,
                "description": weakness.description,
                "extended_description": weakness.extended_description,
                "consequences": "; ".join(weakness.consequences),
                "abstraction": weakness.abstraction,
                "status": weakness.status,
                "relationships": {"parents": parents, "children": children, "peers": peers},
                "mitigations": [
                    {"id": f"MIT-{index}", "title": phases or "Mitigation", "text": text}
                    for index, (phases, text) in enumerate(weakness.mitigations, start=1)
                ],
                "detection_notes": " | ".join(weakness.detection_methods),
            }
        )
    _add_inverse_edges(entries)
    return {
        "meta": {
            "schema_version": "2",
            "source": "MITRE CWE XML catalog",
            "source_url": CWE_XML_ZIP_URL,
            "catalog_version": catalog.version,
            "catalog_date": catalog.date,
            "relation_views": list(_RELATION_VIEWS),
            "n_entries": len(entries),
            "seed_ids": list(SEED_IDS),
            "disclaimer": (
                "Parsed subset of the official MITRE CWE catalog covering the thesis "
                "CWE families and their relationship neighborhood. Not the full catalog."
            ),
        },
        "entries": entries,
    }


def build_and_write(
    root: Path | None = None,
    dest: Path | None = None,
    seed_ids: tuple[str, ...] = SEED_IDS,
    hops: int = 1,
) -> Path:
    xml_path = ensure_cwe_xml(root)
    catalog = parse_catalog(xml_path)
    ids = expand_ids(catalog, seed_ids=seed_ids, hops=hops)
    payload = build_knowledge_payload(catalog, ids)
    out = dest or ((root or repo_root()) / "data" / "cwe" / "knowledge.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return out


def _text(elem: ElementTree.Element | None) -> str:
    if elem is None:
        return ""
    return re.sub(r"\s+", " ", "".join(elem.itertext())).strip()


def _relations(weakness: ElementTree.Element) -> tuple[tuple[str, str], ...]:
    block = weakness.find(f"{_NS}Related_Weaknesses")
    if block is None:
        return ()
    triples = [
        (rel.get("Nature", ""), f"CWE-{rel.get('CWE_ID', '')}", rel.get("View_ID", ""))
        for rel in block.findall(f"{_NS}Related_Weakness")
    ]
    triples = [item for item in triples if item[0] in {"ChildOf", "ParentOf", "PeerOf"} and item[2] in _RELATION_VIEWS]
    # Prefer view 1000 relations; fall back to 699 only when none exist.
    preferred = [item for item in triples if item[2] == "1000"] or [item for item in triples if item[2] == "699"]
    return tuple(dict.fromkeys((nature, other) for nature, other, _view in preferred))


def _split_relations(weakness: RawWeakness, catalog: _Catalog) -> tuple[list[str], list[str], list[str]]:
    parents: list[str] = []
    children: list[str] = []
    peers: list[str] = []
    for nature, other in weakness.relations:
        if other not in catalog.weaknesses:
            continue
        if nature == "ChildOf":
            parents.append(other)
        elif nature == "ParentOf":
            children.append(other)
        else:
            peers.append(other)
    return parents, children, peers


def _add_inverse_edges(entries: list[dict]) -> None:
    """Make the subset graph bidirectionally consistent: MITRE lists ChildOf on
    the child element without always listing ParentOf on the parent, so derive
    the missing inverse edges inside the subset."""
    by_id = {entry["id"]: entry for entry in entries}
    for entry in entries:
        rel = entry["relationships"]
        for parent in list(rel["parents"]):
            target = by_id.get(parent)
            if target is not None and entry["id"] not in target["relationships"]["children"]:
                target["relationships"]["children"].append(entry["id"])
        for child in list(rel["children"]):
            target = by_id.get(child)
            if target is not None and entry["id"] not in target["relationships"]["parents"]:
                target["relationships"]["parents"].append(entry["id"])
        for peer in list(rel["peers"]):
            target = by_id.get(peer)
            if target is not None and entry["id"] not in target["relationships"]["peers"]:
                target["relationships"]["peers"].append(entry["id"])


def _consequences(weakness: ElementTree.Element) -> tuple[str, ...]:
    found: list[str] = []
    block = weakness.find(f"{_NS}Common_Consequences")
    if block is None:
        return ()
    for cons in block.findall(f"{_NS}Consequence"):
        scopes = [_text(item) for item in cons.findall(f"{_NS}Scope")]
        impacts = [_text(item) for item in cons.findall(f"{_NS}Impact")]
        found.append(f"{'/'.join(scopes)}: {', '.join(impacts)}")
    return tuple(found)


def _mitigations(weakness: ElementTree.Element) -> tuple[tuple[str, str], ...]:
    found: list[tuple[str, str]] = []
    block = weakness.find(f"{_NS}Potential_Mitigations")
    if block is None:
        return ()
    for mit in block.findall(f"{_NS}Mitigation"):
        phases = ", ".join(_text(item) for item in mit.findall(f"{_NS}Phase"))
        found.append((phases, _text(mit.find(f"{_NS}Description"))))
    return tuple(found)


def _detection_methods(weakness: ElementTree.Element) -> tuple[str, ...]:
    found: list[str] = []
    block = weakness.find(f"{_NS}Detection_Methods")
    if block is None:
        return ()
    for method in block.findall(f"{_NS}Detection_Method"):
        name = _text(method.find(f"{_NS}Method"))
        desc = _text(method.find(f"{_NS}Description"))
        found.append(f"{name}: {desc}" if name else desc)
    return tuple(found)


if __name__ == "__main__":
    path = build_and_write()
    print(f"wrote {path}")
