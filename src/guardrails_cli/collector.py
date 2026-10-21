from __future__ import annotations

import json
import hashlib
import platform
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

COLLECTOR_SNAPSHOT_SCHEMA = "guardrails.collector-snapshot.v1"


def build_collector_snapshot(*, ide: str, device_id: str, device_name: str, extensions: list[dict[str, Any]]) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    system = platform.system().lower()
    platform_name = {"darwin": "macos", "windows": "windows", "linux": "linux"}.get(system, "other")
    inventory = {}
    for row in extensions:
        extension_id = str(row.get("extension_id") or "").strip()
        version = str(row.get("version") or "").strip()
        if extension_id and version:
            inventory[extension_id.lower()] = {"extension_id": extension_id, "version": version, "registry": "unknown", "artifact_sha256": _hash(row)}
    subjects = []
    for name, config in discover_mcp_servers(ide).items():
        subjects.append({
            "id": f"mcp_server:{_identity(name)}",
            "kind": "mcp_server",
            "name": name,
            "version": None,
            "publisher": None,
            "artifactSha256": None,
            "evidenceState": "observed",
            "observedAt": now,
            "capabilities": _mcp_capabilities(config),
            "source": "collector",
        })
    return {
        "schema_version": COLLECTOR_SNAPSHOT_SCHEMA,
        "inventory": {"device": {"id": device_id, "name": device_name, "platform": platform_name}, "reported_at": now, "source": "api", "extensions": sorted(inventory.values(), key=lambda item: item["extension_id"].lower())},
        "graph": {"generatedAt": now, "subjects": subjects, "relationships": []},
    }


def discover_mcp_servers(ide: str, home: Path | None = None) -> dict[str, dict[str, Any]]:
    root = home or Path.home()
    paths = [root / ".vscode" / "mcp.json"]
    if ide == "cursor": paths.append(root / ".cursor" / "mcp.json")
    if ide == "windsurf": paths.append(root / ".codeium" / "windsurf" / "mcp_config.json")
    servers: dict[str, dict[str, Any]] = {}
    for path in paths:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        raw = value.get("servers") or value.get("mcpServers") if isinstance(value, dict) else None
        if not isinstance(raw, dict):
            continue
        for name, config in raw.items():
            if isinstance(name, str) and isinstance(config, dict):
                servers.setdefault(name[:160], config)
    return servers


def collector_idempotency_key(snapshot: dict[str, Any]) -> str:
    return "grc-" + hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def upload_collector_snapshot(server: str, api_key: str, snapshot: dict[str, Any], timeout: int = 30, retries: int = 2) -> dict[str, Any]:
    key = collector_idempotency_key(snapshot)
    for attempt in range(retries + 1):
        request = Request(server.rstrip("/") + "/api/collector/capabilities", data=json.dumps(snapshot).encode("utf-8"), method="POST", headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "Idempotency-Key": key, "User-Agent": "guardrails-collector/0.2"})
        try:
            with urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            if error.code not in {408, 429, 500, 502, 503, 504} or attempt == retries: raise ValueError(f"Collector upload failed: HTTP {error.code} {error.read().decode('utf-8', errors='replace')}") from error
        except URLError as error:
            if attempt == retries: raise OSError(f"Collector upload failed: {error.reason}") from error
        time.sleep(min(2 ** attempt, 4))
    raise OSError("Collector upload failed after retries.")


def default_device_id(ide: str) -> str:
    digest = __import__("hashlib").sha256(f"{socket.gethostname()}:{ide}".encode("utf-8")).hexdigest()[:16]
    return f"guardrails:{ide}:{digest}"


def _mcp_capabilities(config: dict[str, Any]) -> list[str]:
    capabilities = []
    if isinstance(config.get("command"), str): capabilities.append("process")
    if isinstance(config.get("url"), str): capabilities.append("network")
    if isinstance(config.get("env"), dict) and config["env"]: capabilities.append("secret")
    return capabilities


def _identity(value: str) -> str:
    compact = re.sub(r"[^a-z0-9._:@/-]+", "-", value.strip().lower()).strip("-")
    return compact[:300] or "unnamed"


def _hash(row: dict[str, Any]) -> str | None:
    value = str(row.get("artifact_sha256") or "").lower()
    return value if re.fullmatch(r"[0-9a-f]{64}", value) else None
