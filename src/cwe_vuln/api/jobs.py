"""One-at-a-time job store for operator runs.

Jobs persist under ``results/jobs/`` so a browser refresh does not lose a run.
A second live job is rejected: one Groq key and the daily token cap cannot
safely run two suites at once.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cwe_vuln.config import repo_root
from cwe_vuln.framework.context import RunContext
from cwe_vuln.framework.trials import redact


def jobs_dir(root: Path | None = None) -> Path:
    path = (root or repo_root()) / "results" / "jobs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class JobStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._active: str | None = None

    def _path(self, job_id: str) -> Path:
        return jobs_dir(self.root) / f"{job_id}.json"

    def get(self, job_id: str) -> dict[str, Any] | None:
        path = self._path(job_id)
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _write(self, payload: dict[str, Any]) -> None:
        path = self._path(str(payload["id"]))
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def active(self) -> dict[str, Any] | None:
        with self._lock:
            if self._active is None:
                return None
            job_id = self._active
        return self.get(job_id)

    def submit(self, spec: dict[str, Any], runner) -> dict[str, Any]:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("a job is already running")
            job_id = uuid.uuid4().hex[:12]
            payload = {
                "id": job_id,
                "status": "running",
                "spec": spec,
                "command": spec.get("command"),
                "created_at": _now(),
                "started_at": _now(),
                "finished_at": None,
                "exit_code": None,
                "error": None,
                "log": [],
            }
            self._write(payload)
            self._active = job_id
            self._stop = threading.Event()
            self._thread = threading.Thread(
                target=self._execute,
                args=(job_id, runner),
                name=f"cwe-job-{job_id}",
                daemon=True,
            )
            self._thread.start()
        stored = self.get(job_id)
        assert stored is not None
        return stored

    def append_log(self, job_id: str, line: str) -> None:
        text = redact(line)
        with self._lock:
            payload = self.get(job_id)
            if payload is None:
                return
            log = list(payload.get("log") or [])
            log.append(text)
            payload["log"] = log[-200:]
            self._write(payload)

    def cancel(self, job_id: str) -> dict[str, Any] | None:
        payload = self.get(job_id)
        if payload is None:
            return None
        if payload.get("status") == "running":
            self._stop.set()
            self.append_log(job_id, "cancel requested; stops between units")
        return self.get(job_id)

    def context_for(self, job_id: str) -> RunContext:
        return RunContext(
            should_stop=self._stop.is_set,
            log=lambda line, job_id=job_id: self.append_log(job_id, line),
        )

    def _execute(self, job_id: str, runner) -> None:
        status = "ok"
        error = None
        code = 0
        try:
            code = int(runner(self.context_for(job_id)))
            if self._stop.is_set():
                status = "cancelled"
            elif code != 0:
                status = "failed"
                error = f"exit {code}"
        except Exception as exc:
            status = "failed"
            error = redact(str(exc))
            code = 1
            self.append_log(job_id, error)
        with self._lock:
            payload = self.get(job_id) or {"id": job_id, "log": []}
            payload["status"] = status
            payload["exit_code"] = code
            payload["error"] = error
            payload["finished_at"] = _now()
            self._write(payload)
            if self._active == job_id:
                self._active = None
