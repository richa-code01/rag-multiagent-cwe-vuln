"""Operator API tests. The pipeline and thesis runner are mocked; no live LLM."""

from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from cwe_vuln.api.app import app
from cwe_vuln.api.catalog import save_spotcheck
from cwe_vuln.api.commands import command_for
from cwe_vuln.config import MissingLLMKeyError


def test_command_preview_matches_cli_flags() -> None:
    offline = command_for({"kind": "pipeline", "split": "test", "offline": True})
    assert offline == "uv run cwe-vuln-pipeline --split test --offline"
    thesis = command_for(
        {
            "kind": "eval",
            "suite": "thesis",
            "resume": True,
            "max_tokens": 200000,
            "include_model_ablation": True,
            "offline": False,
            "ablation": "none",
        }
    )
    assert thesis == (
        "uv run cwe-vuln-eval --suite thesis --resume --max-tokens 200000 --include-model-ablation"
    )


def test_console_and_catalog() -> None:
    client = TestClient(app)
    page = client.get("/")
    assert page.status_code == 200
    assert "cwe-vuln operator" in page.text
    catalog = client.get("/api/catalog")
    assert catalog.status_code == 200
    body = catalog.json()
    assert "thesis" in body["eval_suites"]
    assert "groq" in {row["name"] for row in body["providers"]}
    assert "api_key" not in page.text


def test_seed_pipeline_job_uses_offline_flag(monkeypatch) -> None:
    seen: dict[str, list[str]] = {}

    def fake_pipeline(argv: list[str] | None = None) -> int:
        seen["argv"] = list(argv or [])
        return 0

    monkeypatch.setattr("cwe_vuln.framework.cli.main", fake_pipeline)
    client = TestClient(app)
    created = client.post("/api/jobs", json={"kind": "pipeline", "split": "test", "offline": True})
    assert created.status_code == 200
    job_id = created.json()["id"]
    payload = created.json()
    for _ in range(50):
        payload = client.get(f"/api/jobs/{job_id}").json()
        if payload["status"] != "running":
            break
        time.sleep(0.05)
    assert payload["status"] == "ok"
    assert seen["argv"] == ["--split", "test", "--offline"]
    assert "gsk_" not in json.dumps(payload)


def test_unknown_suite_rejected() -> None:
    client = TestClient(app)
    response = client.post("/api/jobs", json={"kind": "eval", "suite": "not-a-suite"})
    assert response.status_code == 400


def test_inspect_offline_is_mocked(monkeypatch) -> None:
    class Report:
        def to_dict(self) -> dict:
            return {"path": "sast_then_llm", "reasoner": "template", "reasoning": {"decision": "vulnerable"}}

    class FakePipeline:
        def run(self, unit):
            return Report()

    monkeypatch.setattr("cwe_vuln.orchestrator.Pipeline.offline", staticmethod(lambda: FakePipeline()))
    client = TestClient(app)
    response = client.post("/api/inspect", json={"unit_id": "java_cwe89_sqli_concat", "offline": True})
    assert response.status_code == 200
    assert response.json()["reasoning"]["decision"] == "vulnerable"


def test_live_inspect_without_key_is_rejected(monkeypatch) -> None:
    def explode():
        raise MissingLLMKeyError("set GROQ_API_KEY")

    monkeypatch.setattr("cwe_vuln.orchestrator.Pipeline.default", staticmethod(explode))
    client = TestClient(app)
    response = client.post(
        "/api/inspect",
        json={"source": "class X { int a; }", "offline": False},
    )
    assert response.status_code == 400
    assert "GROQ_API_KEY" in response.json()["detail"]


def test_incomplete_spotcheck_stays_not_run(tmp_path: Path) -> None:
    dest = tmp_path / "results" / "thesis"
    dest.mkdir(parents=True)
    (dest / "human_spotcheck.json").write_text(
        json.dumps(
            {
                "status": "not_run",
                "rows": [
                    {"unit_id": "a", "explanation_correct": None, "remediation_useful": None},
                    {"unit_id": "b", "explanation_correct": None, "remediation_useful": None},
                ],
            }
        ),
        encoding="utf-8",
    )
    saved = save_spotcheck(
        [{"unit_id": "a", "explanation_correct": True, "remediation_useful": None}],
        root=tmp_path,
    )
    assert saved["status"] == "not_run"
    assert saved["n_labeled"] == 0
