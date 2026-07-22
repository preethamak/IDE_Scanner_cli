from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import threading
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .report_bundle import build_report_bundle
from .rule_registry import RULESET_VERSION, rules_json
from .scanner import scan_targets

SERVICE_VERSION = "0.1.0"
DEFAULT_DATA_DIR = Path(os.environ.get("IDE_SCANNER_DATA_DIR", ".ide-scanner-data"))
MARKETPLACE_ID = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$")


class JobStore:
    def __init__(self, root: Path = DEFAULT_DATA_DIR) -> None:
        self.root = root
        self.jobs_dir = root / "jobs"
        self.reports_dir = root / "reports"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def create(self, extension_id: str) -> dict[str, Any]:
        now = _now()
        job = {
            "id": f"job_{uuid.uuid4().hex}",
            "status": "queued",
            "extension_id": extension_id,
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
        temp = path.with_suffix(".tmp")
        with self._lock:
            temp.write_text(json.dumps(job, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            temp.replace(path)

    def write_report(self, job_id: str, report: dict[str, Any]) -> str:
        path = self.reports_dir / f"{job_id}.json"
        temp = path.with_suffix(".tmp")
        with self._lock:
            temp.write_text(json.dumps(report, separators=(",", ":"), sort_keys=True), encoding="utf-8")
            temp.replace(path)
        return f"/v1/reports/{job_id}"

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


def execute_marketplace_job(
    store: JobStore,
    job: dict[str, Any],
    scan: Callable[..., dict[str, Any]] = scan_targets,
) -> None:
    job["status"] = "running"
    job["stage"] = "downloading"
    store.write(job)
    try:
        report = scan(marketplace_scan_ids=[job["extension_id"]], online=True, include_posture=False)
        bundle = build_report_bundle(report, profile="deep", source="marketplace")
        extension_rows = bundle.get("leaderboard", {}).get("extensions", [])
        if not extension_rows:
            raise RuntimeError("Scanner completed without an extension result.")
        job["status"] = "complete"
        job["stage"] = "complete"
        job["summary"] = bundle["summary"]
        job["report_ref"] = store.write_report(job["id"], bundle)
        store.write(job)
    except Exception as exc:  # noqa: BLE001 - job records must surface scanner/network failures
        job["status"] = "failed"
        job["stage"] = "failed"
        job["error"] = str(exc)
        store.write(job)


class ScannerServiceHandler(BaseHTTPRequestHandler):
    server_version = "IDEScannerService/0.1"

    @property
    def store(self) -> JobStore:
        return self.server.job_store  # type: ignore[attr-defined]

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
        job = self.store.create(extension_id)
        threading.Thread(target=execute_marketplace_job, args=(self.store, job), daemon=True).start()
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
    server = ThreadingHTTPServer((host, port), ScannerServiceHandler)
    server.job_store = JobStore(data_dir)  # type: ignore[attr-defined]
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
