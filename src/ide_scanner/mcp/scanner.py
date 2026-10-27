from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any, Coroutine

from .orchestrator import ServerCatalogRiskConfig, ServerCatalogRiskOrchestrator


def scan_mcp_path(path: str | Path, *, config: ServerCatalogRiskConfig | None = None) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("MCP assessment input must be a JSON object.")
    payload.setdefault("source", {})
    if isinstance(payload["source"], dict):
        payload["source"].update({"path": str(source), "mode": "full"})
    return scan_mcp_payload(payload, config=config)


def scan_mcp_payload(payload: dict[str, Any], *, config: ServerCatalogRiskConfig | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("MCP assessment input must be a JSON object.")
    raw = payload.get("server") if isinstance(payload.get("server"), dict) else payload
    normalized = _normalize_input(raw)
    return _run_sync(ServerCatalogRiskOrchestrator(config=config).evaluate(normalized))


def _normalize_input(raw: dict[str, Any]) -> dict[str, Any]:
    url = str(raw.get("mcp_url") or raw.get("url") or "").strip()
    transport = str(raw.get("transport") or raw.get("transport_type") or "").lower().strip()
    is_local = bool(raw.get("is_local")) or transport in {"stdio", "local", "command"} or not url
    auth_modes = raw.get("auth_modes") or raw.get("authentication")
    if isinstance(auth_modes, str):
        auth_modes = [auth_modes]
    return {
        **raw,
        "mcp_url": url or None,
        "url": url or None,
        "is_local": is_local,
        "transport": transport or ("stdio" if is_local else "streamable-http"),
        "repo_url": str(raw.get("repo_url") or raw.get("repository") or raw.get("repository_url") or "").strip() or None,
        "package": raw.get("package") or raw.get("install_command") or raw.get("command"),
        "tools": raw.get("tools") if isinstance(raw.get("tools"), list) else [],
        "auth_modes": auth_modes if isinstance(auth_modes, list) else [],
    }


def _run_sync(coroutine: Coroutine[Any, Any, dict[str, Any]]) -> dict[str, Any]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    result: list[dict[str, Any]] = []
    error: list[BaseException] = []

    def runner() -> None:
        try:
            result.append(asyncio.run(coroutine))
        except BaseException as exc:  # pragma: no cover - defensive bridge behavior
            error.append(exc)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0]


__all__ = ["scan_mcp_path", "scan_mcp_payload"]

