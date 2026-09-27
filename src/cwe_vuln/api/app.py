"""FastAPI app for the local operator console."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.requests import Request

from cwe_vuln.api.catalog import (
    EVAL_SUITES,
    load_spotcheck,
    load_trial,
    provider_catalog,
    save_spotcheck,
    suite_catalog,
    thesis_summary,
)
from cwe_vuln.api.commands import argv_for, command_for
from cwe_vuln.api.jobs import JobStore
from cwe_vuln.config import MissingLLMKeyError
from cwe_vuln.dataset import SeedUnit, load_research_corpus, load_seed
from cwe_vuln.framework.trials import redact
from cwe_vuln.knowledge import CWEKnowledgeBase, KnowledgeError
from cwe_vuln.orchestrator import Pipeline

_WEB = Path(__file__).resolve().parents[1] / "web"
templates = Jinja2Templates(directory=str(_WEB / "templates"))

app = FastAPI(title="cwe-vuln operator", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(_WEB / "static")), name="static")
store = JobStore()


class JobRequest(BaseModel):
    kind: str = "eval"
    suite: str = "research"
    ablation: str = "none"
    offline: bool = False
    resume: bool = False
    max_tokens: int | None = None
    include_model_ablation: bool = False
    per_cwe: int | None = None
    sample_n: int | None = None
    sample_seed: int | None = None
    split: str = "test"


class InspectRequest(BaseModel):
    unit_id: str | None = None
    source: str | None = None
    cwe_id: str = "CWE-89"
    offline: bool = True


class SpotcheckUpdate(BaseModel):
    rows: list[dict[str, Any]] = Field(default_factory=list)


class RetrieveRequest(BaseModel):
    query: str
    k: int = 5


def _spec(body: JobRequest) -> dict[str, Any]:
    spec = body.model_dump()
    if spec["kind"] == "eval" and spec["suite"] not in EVAL_SUITES:
        raise HTTPException(status_code=400, detail=f"unknown suite {spec['suite']}")
    if spec["kind"] == "pipeline" and spec["split"] not in {"test", "train", "all"}:
        raise HTTPException(status_code=400, detail="split must be test, train, or all")
    if spec["ablation"] not in {"none", "template", "skip-llm"}:
        raise HTTPException(status_code=400, detail="unknown ablation")
    spec["command"] = command_for(spec)
    return spec


def _run_spec(spec: dict[str, Any], context) -> int:
    argv = argv_for(spec)
    if spec.get("kind") == "pipeline":
        from cwe_vuln.framework.cli import main as pipeline_main

        return pipeline_main(argv)
    from cwe_vuln.framework.cli_eval import main as eval_main

    return eval_main(argv, context=context)


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "console.html", {"request": request})


@app.get("/api/catalog")
def catalog() -> dict[str, Any]:
    return {**suite_catalog(), **provider_catalog()}


@app.get("/api/results")
def results() -> dict[str, Any]:
    return thesis_summary()


@app.get("/api/results/{trial_id}")
def trial(trial_id: str) -> dict[str, Any]:
    payload = load_trial(trial_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="trial not found")
    return payload


@app.post("/api/jobs")
def create_job(body: JobRequest) -> dict[str, Any]:
    spec = _spec(body)
    try:
        return store.submit(spec, lambda context, spec=spec: _run_spec(spec, context))
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/jobs/active")
def active_job() -> dict[str, Any]:
    job = store.active()
    return {"job": job}


@app.get("/api/jobs/{job_id}")
def read_job(job_id: str) -> dict[str, Any]:
    payload = store.get(job_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="job not found")
    return payload


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str) -> dict[str, Any]:
    payload = store.cancel(job_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="job not found")
    return payload


def _lookup_unit(unit_id: str) -> SeedUnit | None:
    for loader in (load_seed, lambda: load_research_corpus()):
        for unit in loader():
            if unit.unit_id == unit_id:
                return unit
    return None


@app.post("/api/inspect")
def inspect(body: InspectRequest) -> dict[str, Any]:
    if body.unit_id:
        unit = _lookup_unit(body.unit_id)
        if unit is None:
            raise HTTPException(status_code=404, detail=f"unknown unit {body.unit_id}")
    elif body.source and body.source.strip():
        if len(body.source) > 200_000:
            raise HTTPException(status_code=400, detail="source is too long")
        unit = SeedUnit(
            unit_id="pasted",
            cwe_id=body.cwe_id,
            path="Snippet.java",
            split="test",
            label="not_vulnerable",
            notes="operator paste; label is not gold",
            source=body.source,
            trap_type="paste",
            corpus="operator",
        )
    else:
        raise HTTPException(status_code=400, detail="provide unit_id or source")
    try:
        pipeline = Pipeline.offline() if body.offline else Pipeline.default()
        report = pipeline.run(unit).to_dict()
    except MissingLLMKeyError as exc:
        raise HTTPException(status_code=400, detail=redact(str(exc))) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=redact(str(exc))) from exc
    report["offline"] = body.offline
    report["gold_label_used"] = False if body.source else unit.label
    return report


@app.get("/api/kb/{cwe_id}")
def kb_get(cwe_id: str) -> dict[str, Any]:
    kb = CWEKnowledgeBase.load()
    try:
        entry = kb.get(cwe_id)
    except KnowledgeError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    rel = kb.relationships(entry.id)
    return {
        "id": entry.id,
        "name": entry.name,
        "description": entry.description,
        "parents": list(rel.parents),
        "children": list(rel.children),
        "peers": list(rel.peers),
        "mitigations": [{"id": item.id, "title": item.title, "text": item.text} for item in kb.mitigations(entry.id)],
    }


@app.get("/api/kb")
def kb_search(q: str, limit: int = 5) -> dict[str, Any]:
    kb = CWEKnowledgeBase.load()
    hits = kb.search(q, limit=limit)
    return {
        "hits": [{"id": entry.id, "name": entry.name, "score": round(score, 3)} for entry, score in hits]
    }


@app.post("/api/retrieve")
def retrieve(body: RetrieveRequest) -> dict[str, Any]:
    from cwe_vuln.retrieval import HybridRetriever, RetrievalQuery

    retriever = HybridRetriever.load(allow_download=False)
    query = RetrievalQuery(query_id="ui", query=body.query, relevant_cwes=(), unit_id=None)
    hits = retriever.hybrid_rank(query)[: body.k]
    return {
        "embedder": retriever.embedder_name,
        "hits": [
            {"cwe_id": hit.cwe_id, "score": hit.score, "name": hit.name, "passage": hit.passage}
            for hit in hits
        ],
    }


@app.get("/api/spotcheck")
def spotcheck() -> dict[str, Any]:
    return load_spotcheck()


@app.post("/api/spotcheck")
def spotcheck_save(body: SpotcheckUpdate) -> dict[str, Any]:
    return save_spotcheck(body.rows)
