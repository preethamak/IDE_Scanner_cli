from __future__ import annotations

import argparse
import hmac
import json
import os
import queue
import re
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .artifact_store import TARGET_PLATFORM_RE
from .report_bundle import build_report_bundle
from .rule_registry import RULESET_VERSION, rules_json
from .scanner import scan_targets

SERVICE_VERSION = "0.1.0"
DEFAULT_DATA_DIR = Path(os.environ.get("IDE_SCANNER_DATA_DIR", ".ide-scanner-data"))
MARKETPLACE_ID = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$")


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


# Bounded worker pool + queue so a burst of scan requests cannot spawn
# unbounded threads or downloads. Excess requests are rejected with 429 rather
# than silently queued forever.
MAX_SCAN_WORKERS = _bounded_env_int("IDE_SCANNER_MAX_WORKERS", 2, 1, 16)
MAX_SCAN_QUEUE = _bounded_env_int("IDE_SCANNER_MAX_QUEUE", 32, 1, 1024)
JOB_TIMEOUT_SECONDS = _bounded_env_int("IDE_SCANNER_JOB_TIMEOUT", 600, 30, 3600)


class JobStore:
    def __init__(self, root: Path = DEFAULT_DATA_DIR) -> None:
        self.root = root
        self.jobs_dir = root / "jobs"
        self.reports_dir = root / "reports"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def create(self, extension_id: str, *, version: str | None = None, target_platform: str | None = None) -> dict[str, Any]:
        now = _now()
        job = {
            "id": f"job_{uuid.uuid4().hex}",
            "status": "queued",
            "extension_id": extension_id,
            "version": version,
            "target_platform": target_platform,
            "created_at": now,
            "updated_at": now,
            "error": None,
            "report_ref": None,
        }
        self.write(job)
        return job

    def get(self, job_id: str) -> dict[str, Any] | None:
        if not re.fullmatch(r"job_[a-f0-9]{32}", job_id):
            return None
        path = self.jobs_dir / f"{job_id}.json"
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def write(self, job: dict[str, Any]) -> None:
        job["updated_at"] = _now()
        path = self.jobs_dir / f"{job['id']}.json"
        with self._lock:
            self._write_json_locked(path, job)

    def write_report(self, job_id: str, report: dict[str, Any]) -> str:
        path = self.reports_dir / f"{job_id}.json"
        with self._lock:
            self._write_json_locked(path, report, separators=(",", ":"))
        return f"/v1/reports/{job_id}"

    def try_complete(self, job_id: str, summary: dict[str, Any], report: dict[str, Any]) -> bool:
        """Commit a report only if this job is still owned by its runner.

        Timeout handling deliberately cannot kill a Python thread. A late
        runner must therefore lose the terminal-state race instead of turning
        a previously failed job back into a successful one.
        """
        job_path = self.jobs_dir / f"{job_id}.json"
        report_path = self.reports_dir / f"{job_id}.json"
        with self._lock:
            current = self._read_json_locked(job_path)
            if not isinstance(current, dict) or current.get("status") != "running":
                return False
            self._write_json_locked(report_path, report, separators=(",", ":"))
            current.update({
                "status": "complete",
                "stage": "complete",
                "summary": summary,
                "report_ref": f"/v1/reports/{job_id}",
                "updated_at": _now(),
            })
            self._write_json_locked(job_path, current)
            return True

    def try_fail(self, job_id: str, error: str, *, stage: str = "failed") -> bool:
        """Fail a non-terminal job without overwriting a prior terminal state."""
        path = self.jobs_dir / f"{job_id}.json"
        with self._lock:
            current = self._read_json_locked(path)
            if not isinstance(current, dict) or current.get("status") not in {"queued", "running"}:
                return False
            current.update({
                "status": "failed",
                "stage": stage,
                "error": error,
                "updated_at": _now(),
            })
            self._write_json_locked(path, current)
            return True

    def get_report(self, job_id: str) -> dict[str, Any] | None:
        if not re.fullmatch(r"job_[a-f0-9]{32}", job_id):
            return None
        path = self.reports_dir / f"{job_id}.json"
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    @staticmethod
    def _read_json_locked(path: Path) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def _write_json_locked(path: Path, value: Any, *, separators: tuple[str, str] | None = None) -> None:
        temp = path.with_suffix(".tmp")
        kwargs: dict[str, Any] = {"sort_keys": True}
        if separators is not None:
            kwargs["separators"] = separators
        temp.write_text(json.dumps(value, indent=None if separators else 2, **kwargs) + ("" if separators else "\n"), encoding="utf-8")
        temp.replace(path)


def execute_marketplace_job(
    store: JobStore,
    job: dict[str, Any],
    scan: Callable[..., dict[str, Any]] = scan_targets,
) -> None:
    from .scanner import DEEP_REQUIRED_PROVIDERS

    job["status"] = "running"
    job["stage"] = "downloading"
    store.write(job)
    try:
        report = scan(
            marketplace_scan_ids=[job["extension_id"]],
            marketplace_version=job.get("version"),
            marketplace_target_platform=job.get("target_platform"),
            online=True,
            include_posture=False,
            required_providers=DEEP_REQUIRED_PROVIDERS,
            dynamic_runtime=True,
            runtime_timeout_seconds=20,
        )
        bundle = build_report_bundle(report, profile="deep", source="marketplace")
        extension_rows = bundle.get("leaderboard", {}).get("extensions", [])
        if not extension_rows:
            raise RuntimeError("Scanner completed without an extension result.")
        store.try_complete(job["id"], bundle["summary"], bundle)
    except Exception as exc:  # noqa: BLE001 - job records must surface scanner/network failures
        store.try_fail(job["id"], str(exc))


class ScanWorkerPool:
    """Fixed-size worker pool with a bounded queue and per-job timeout.

    A burst of scan submissions is capped: at most ``max_workers`` scans run
    concurrently, at most ``max_queue`` wait, and anything beyond that is
    rejected so the process cannot be driven into unbounded thread/download
    fan-out. Each job is watched by a timeout that marks it ``failed`` if it
    overruns, so a wedged download or analyzer cannot occupy a worker forever."""

    def __init__(
        self,
        store: JobStore,
        max_workers: int = MAX_SCAN_WORKERS,
        max_queue: int = MAX_SCAN_QUEUE,
        job_timeout: int = JOB_TIMEOUT_SECONDS,
        runner: Callable[[JobStore, dict[str, Any]], None] = execute_marketplace_job,
    ) -> None:
        self.store = store
        self.job_timeout = job_timeout
        self._runner = runner
        self._queue: "queue.Queue[dict[str, Any] | None]" = queue.Queue(maxsize=max_queue)
        self._threads: list[threading.Thread] = []
        for index in range(max_workers):
            thread = threading.Thread(target=self._worker, name=f"scan-worker-{index}", daemon=True)
            thread.start()
            self._threads.append(thread)

    def submit(self, job: dict[str, Any]) -> bool:
        try:
            self._queue.put_nowait(job)
            return True
        except queue.Full:
            return False

    def _worker(self) -> None:
        while True:
            job = self._queue.get()
            if job is None:
                return
            try:
                self._run_with_timeout(job)
            finally:
                self._queue.task_done()

    def _run_with_timeout(self, job: dict[str, Any]) -> None:
        done = threading.Event()

        def _invoke() -> None:
            try:
                self._runner(self.store, job)
            finally:
                done.set()

        worker = threading.Thread(target=_invoke, name=f"scan-run-{job['id']}", daemon=True)
        worker.start()
        if not done.wait(self.job_timeout):
            # The scan overran its budget. Record the timeout; the orphaned
            # daemon thread cannot be force-killed in CPython, but the bounded
            # pool prevents it from starving new work indefinitely.
            self.store.try_fail(
                job["id"],
                f"Scan exceeded the {self.job_timeout}s job timeout and was abandoned.",
                stage="timeout",
            )


def cleanup_stale_jobs(store: JobStore, max_age_seconds: int = 7 * 24 * 3600) -> int:
    """Remove job/report files older than ``max_age_seconds`` and mark any
    ``running``/``queued`` job left over from a previous process as failed, so
    a restart does not leave jobs wedged in a non-terminal state forever."""
    removed = 0
    cutoff = time.time() - max_age_seconds
    for directory in (store.jobs_dir, store.reports_dir):
        for path in directory.glob("*.json"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
                    removed += 1
            except OSError:
                continue
    for path in store.jobs_dir.glob("job_*.json"):
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(job, dict) and job.get("status") in {"queued", "running"}:
            job["status"] = "failed"
            job["stage"] = "interrupted"
            job["error"] = "Service restarted while the job was in progress."
            store.write(job)
    return removed


class ScannerServiceHandler(BaseHTTPRequestHandler):
    server_version = "IDEScannerService/0.1"

    @property
    def store(self) -> JobStore:
        return self.server.job_store  # type: ignore[attr-defined]

    @property
    def pool(self) -> "ScanWorkerPool":
        return self.server.scan_pool  # type: ignore[attr-defined]

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._json(200, health_payload())
            return
        if path == "/v1/rules":
            self._json(200, rules_json())
            return
        if not self._authorized():
            self._json(401, {"error": "Scanner service authorization failed."})
            return
        if path.startswith("/v1/jobs/"):
            job = self.store.get(path.rsplit("/", 1)[-1])
            self._json(200, job) if job else self._json(404, {"error": "Scan job not found."})
            return
        if path.startswith("/v1/reports/"):
            report = self.store.get_report(path.rsplit("/", 1)[-1])
            self._json(200, report) if report else self._json(404, {"error": "Scan report not found."})
            return
        self._json(404, {"error": "Route not found."})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            self._json(401, {"error": "Scanner service authorization failed."})
            return
        if self.path.split("?", 1)[0] != "/v1/scans/marketplace":
            self._json(404, {"error": "Route not found."})
            return
        payload = self._read_json()
        extension_id = str(payload.get("extension_id") or "").strip()
        if not MARKETPLACE_ID.fullmatch(extension_id):
            self._json(400, {"error": "extension_id must use publisher.extension format."})
            return
        version = str(payload.get("version") or "").strip() or None
        target_platform = str(payload.get("target_platform") or "").strip().lower() or None
        if target_platform and not TARGET_PLATFORM_RE.fullmatch(target_platform):
            self._json(400, {"error": "target_platform is invalid."})
            return
        job = self.store.create(extension_id, version=version, target_platform=target_platform)
        if not self.pool.submit(job):
            job["status"] = "failed"
            job["stage"] = "rejected"
            job["error"] = "Scanner is at capacity; retry later."
            self.store.write(job)
            self._json(429, {"error": "Scanner is at capacity; retry later.", "job": job})
            return
        self._json(202, job)

    def log_message(self, format: str, *args: object) -> None:
        if os.environ.get("IDE_SCANNER_QUIET") != "1":
            super().log_message(format, *args)

    def _read_json(self) -> dict[str, Any]:
        try:
            length = min(int(self.headers.get("content-length", "0")), 16_384)
            value = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def _authorized(self) -> bool:
        token = os.environ.get("IDE_SCANNER_API_TOKEN", "")
        if not token:
            return True
        supplied = self.headers.get("authorization", "")
        return hmac.compare_digest(supplied, f"Bearer {token}")

    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _cors_headers(self) -> None:
        origin = os.environ.get("IDE_SCANNER_ALLOWED_ORIGIN", "http://127.0.0.1:8765")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Headers", "content-type, authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")


def health_payload() -> dict[str, Any]:
    return {
        "status": "ok",
        "service_version": SERVICE_VERSION,
        "ruleset_version": RULESET_VERSION,
        "providers": {
            "native_static": "available",
            "javascript_ast": "available",
            "semgrep": "optional",
            "yara": "optional",
            "dependency_intelligence": "online",
        },
    }


def serve(host: str = "127.0.0.1", port: int = 8787, data_dir: Path = DEFAULT_DATA_DIR) -> None:
    token = os.environ.get("IDE_SCANNER_API_TOKEN", "")
    non_loopback = host not in {"127.0.0.1", "::1", "localhost"}
    if non_loopback and not token:
        if os.environ.get("IDE_SCANNER_ALLOW_INSECURE_BIND") != "1":
            raise SystemExit(
                f"Refusing to bind {host}:{port} without IDE_SCANNER_API_TOKEN. "
                "Set a token, bind to 127.0.0.1, or explicitly set "
                "IDE_SCANNER_ALLOW_INSECURE_BIND=1 for a trusted local network only."
            )
        print(
            f"WARNING: binding {host}:{port} with no API token; scan endpoints are unauthenticated.",
            file=sys.stderr,
        )
    store = JobStore(data_dir)
    cleanup_stale_jobs(store)
    server = ThreadingHTTPServer((host, port), ScannerServiceHandler)
    server.job_store = store  # type: ignore[attr-defined]
    server.scan_pool = ScanWorkerPool(store)  # type: ignore[attr-defined]
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ide-scanner-service", description="Run the IDE Scanner HTTP job service.")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8787")))
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    args = parser.parse_args(argv)
    serve(args.host, args.port, args.data_dir)
    return 0


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
