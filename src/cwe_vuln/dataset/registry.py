"""Registry of public Java suites for cwe-vuln-eval --suite <name>."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from cwe_vuln.dataset.cvefixes import (
    SUITE as CVEFIXES,
    ensure_cvefixes_slice,
    load_cvefixes_units,
    mapping_notes as cvefixes_notes,
    provenance_path as cvefixes_prov,
    sample_manifest_path as cvefixes_sample,
)
from cwe_vuln.dataset.findsecbugs import (
    SUITE as FSB,
    ensure_findsecbugs,
    load_findsecbugs_units,
    mapping_notes as fsb_notes,
    provenance_path as fsb_prov,
    sample_manifest_path as fsb_sample,
)
from cwe_vuln.dataset.juliet import (
    JULIET_VERSION,
    ensure_juliet,
    load_juliet_units,
    mapping_notes as juliet_notes,
    provenance_path as juliet_prov,
    sample_manifest_path as juliet_sample,
)
from cwe_vuln.dataset.owasp import (
    SUITE as OWASP,
    ensure_owasp,
    load_owasp_units,
    mapping_notes as owasp_notes,
    provenance_path as owasp_prov,
    sample_manifest_path as owasp_sample,
)
from cwe_vuln.dataset.securibench import (
    SUITE as SECURIBENCH,
    ensure_securibench,
    load_securibench_units,
    mapping_notes as sb_notes,
    provenance_path as sb_prov,
    sample_manifest_path as sb_sample,
)
from cwe_vuln.dataset.seed import SeedUnit
from cwe_vuln.dataset.vul4j import (
    SUITE as VUL4J,
    ensure_vul4j,
    load_vul4j_units,
    mapping_notes as vul4j_notes,
    provenance_path as vul4j_prov,
    sample_manifest_path as vul4j_sample,
)

Loader = Callable[..., list[SeedUnit]]
EnsureFn = Callable[..., Any]
NotesFn = Callable[..., dict[str, Any]]


class SuiteSpec:
    def __init__(
        self,
        name: str,
        loader: Loader,
        ensure: EnsureFn,
        notes: NotesFn,
        provenance: Callable[..., Path],
        sample_manifest: Callable[..., Path],
        evaluation_scope: str,
        disclaimer: str,
    ) -> None:
        self.name = name
        self.loader = loader
        self.ensure = ensure
        self.notes = notes
        self.provenance = provenance
        self.sample_manifest = sample_manifest
        self.evaluation_scope = evaluation_scope
        self.disclaimer = disclaimer


JULIET_DISCLAIMER = (
    "Juliet Java public-benchmark subset. Not the authored 36-unit research table. "
    "LLM scores are on a stratified sample only. Nearby CWE folders keep Juliet ids."
)

PUBLIC_DISCLAIMER = (
    "Public/industry-style Java suite. Regex SAST is not CodeQL. "
    "LLM scores are on a deterministic stratified sample, not the full ingested set. "
    "Six-suite measurement does not prove 100% novelty; the claim is this method "
    "(SAST evidence + hybrid CWE retrieval + schema-bound Groq) vs these corpora/baselines."
)


def _juliet_load(tree=None, require_download=False, **_kwargs):
    return load_juliet_units(tree=tree, require_download=require_download)


SUITES: dict[str, SuiteSpec] = {
    "juliet": SuiteSpec(
        name="juliet",
        loader=_juliet_load,
        ensure=ensure_juliet,
        notes=lambda units=None: juliet_notes() if units is None else {**juliet_notes(), "n": len(units)},
        provenance=juliet_prov,
        sample_manifest=juliet_sample,
        evaluation_scope="juliet_java_v1_3_mapped_subset",
        disclaimer=JULIET_DISCLAIMER + f" Juliet {JULIET_VERSION}.",
    ),
    OWASP: SuiteSpec(
        name=OWASP,
        loader=load_owasp_units,
        ensure=ensure_owasp,
        notes=owasp_notes,
        provenance=owasp_prov,
        sample_manifest=owasp_sample,
        evaluation_scope="owasp_benchmark_java",
        disclaimer=PUBLIC_DISCLAIMER,
    ),
    SECURIBENCH: SuiteSpec(
        name=SECURIBENCH,
        loader=load_securibench_units,
        ensure=ensure_securibench,
        notes=sb_notes,
        provenance=sb_prov,
        sample_manifest=sb_sample,
        evaluation_scope="securibench_micro",
        disclaimer=PUBLIC_DISCLAIMER,
    ),
    FSB: SuiteSpec(
        name=FSB,
        loader=load_findsecbugs_units,
        ensure=ensure_findsecbugs,
        notes=fsb_notes,
        provenance=fsb_prov,
        sample_manifest=fsb_sample,
        evaluation_scope="find_sec_bugs_testcode",
        disclaimer=PUBLIC_DISCLAIMER,
    ),
    VUL4J: SuiteSpec(
        name=VUL4J,
        loader=load_vul4j_units,
        ensure=ensure_vul4j,
        notes=vul4j_notes,
        provenance=vul4j_prov,
        sample_manifest=vul4j_sample,
        evaluation_scope="vul4j_thesis_cwes",
        disclaimer=PUBLIC_DISCLAIMER,
    ),
    CVEFIXES: SuiteSpec(
        name=CVEFIXES,
        loader=load_cvefixes_units,
        ensure=ensure_cvefixes_slice,
        notes=cvefixes_notes,
        provenance=cvefixes_prov,
        sample_manifest=cvefixes_sample,
        evaluation_scope="cvefixes_java_slice",
        disclaimer=PUBLIC_DISCLAIMER,
    ),
}

ALIASES = {
    "juliet-sast": "juliet",
    "juliet-llm-sample": "juliet",
}

SAST_SUITE_NAMES = tuple(SUITES.keys())
LLM_SUITE_NAMES = tuple(f"{name}-llm-sample" for name in SUITES)


def resolve_suite(raw: str) -> tuple[str, bool]:
    """Return (canonical suite name, llm_sample?)."""
    if raw.endswith("-llm-sample"):
        base = raw[: -len("-llm-sample")]
        base = ALIASES.get(base, base)
        if base == "juliet-sast":
            base = "juliet"
        if base not in SUITES:
            raise KeyError(raw)
        return base, True
    name = ALIASES.get(raw, raw)
    if name not in SUITES:
        raise KeyError(raw)
    return name, False
