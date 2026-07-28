from __future__ import annotations

import json
import platform
import socket
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .core import ScanRequest, run_scan, summarize_report


def _redact_source_previews(report: dict[str, Any]) -> int:
    """Strip full source-file contents from every extension in the report.

    The scanner captures source previews locally for evidence, but the agent
    upload is a network boundary: the product's privacy claim is that source
    code stays on the machine. We remove the raw preview ``content`` so source
    and secrets captured there cannot leave the host by accident. Path + hash
    metadata is retained so the server can still reason about which files
    existed without receiving their preview bytes."""
    redacted = 0
    extensions = report.get("extensions")
    if not isinstance(extensions, list):
        return 0
    for extension in extensions:
        inventory = extension.get("artifact_inventory") if isinstance(extension, dict) else None
        if not isinstance(inventory, dict):
            continue
        previews = inventory.get("source_previews")
        if isinstance(previews, list) and previews:
            inventory["source_previews"] = [
                {
                    "path": item.get("path"),
                    "content_sha256": item.get("content_sha256"),
                    "redacted": True,
                }
                for item in previews
                if isinstance(item, dict)
            ]
            redacted += len(previews)
    return redacted


def build_agent_report(
    *,
    paths: list[Path],
    all_local: bool,
    online: bool,
    previous_report_file: str | None = None,
    include_source: bool = False,
) -> dict[str, Any]:
    report = run_scan(
        ScanRequest(
            paths=paths,
            all_local=all_local,
            online=online,
            previous_report_file=previous_report_file,
        )
    )
    source_redacted = 0
    if not include_source:
        source_redacted = _redact_source_previews(report)
    return {
        "agent": {
            "schema_version": "0.1.0",
            "generated_at": int(time.time() * 1000),
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "source_included": bool(include_source),
            "source_previews_redacted": source_redacted,
        },
        "summary": summarize_report(report, top_limit=50),
        "report": report,
    }


def upload_agent_report(server_url: str, payload: dict[str, Any], token: str | None = None, timeout: int = 30) -> dict[str, Any]:
    endpoint = server_url.rstrip("/") + "/api/agent/reports"
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "ide-scanner-agent/0.1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(endpoint, data=body, headers=headers, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else {}
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"upload failed: HTTP {error.code} {detail}") from error
    except URLError as error:
        raise RuntimeError(f"upload failed: {error.reason}") from error
