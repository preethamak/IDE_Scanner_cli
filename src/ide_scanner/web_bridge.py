from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from .cli import _run_benchmark
from .core import ScanRequest, build_inventory, run_scan, summarize_report
from .registry import search_marketplace_extensions
from .rule_registry import rules_json
from .sandbox_runner import run_sandbox


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ide-scanner-web-bridge")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("inventory")
    subparsers.add_parser("scan")
    subparsers.add_parser("benchmark")
    subparsers.add_parser("sandbox")
    subparsers.add_parser("search")
    subparsers.add_parser("rules")
    args = parser.parse_args(argv)

    if args.command == "inventory":
        _emit(build_inventory(all_local=True))
        return 0
    if args.command == "scan":
        payload = _read_stdin_json()
        paths = payload.get("extension_paths") or payload.get("paths") or []
        if not isinstance(paths, list) or not all(isinstance(item, str) for item in paths):
            _emit_error("extension_paths must be a list of strings")
            return 2
        marketplace_ids = payload.get("marketplace_ids") or []
        if not isinstance(marketplace_ids, list) or not all(isinstance(item, str) for item in marketplace_ids):
            _emit_error("marketplace_ids must be a list of strings")
            return 2
        # Sandbox dynamic execution only ever runs over locally-supplied
        # `paths` (the local collector-bridge/agent flow, on the operator's
        # own machine). marketplace_ids are attacker-reachable, hosted,
        # server-side downloads and must never be routed through
        # run_sandbox(allow_execute=True) -- scan_marketplace_extension()
        # only performs the static scan_vsix() path and has no sandbox
        # call at all, so this holds structurally, not just by convention.
        sandbox_observations_file: str | None = None
        if payload.get("sandbox") and paths:
            observations = _run_sandboxes(paths, bool(payload.get("allow_execute", False)), int(payload.get("timeout", 15) or 15))
            sandbox_file = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False)
            with sandbox_file:
                json.dump(observations, sandbox_file)
            sandbox_observations_file = sandbox_file.name
        request = ScanRequest(
            paths=[Path(item) for item in paths],
            marketplace_scan_ids=marketplace_ids,
            online=bool(payload.get("online", False)),
            sandbox_observations_file=sandbox_observations_file or payload.get("sandbox_observations_file"),
            previous_report_file=_write_previous_report(payload.get("previous_report")),
            include_posture=bool(payload.get("include_posture", True)),
        )
        report = run_scan(request)
        _emit({
            "summary": summarize_report(report, top_limit=50),
            "report": report,
        })
        return 0
    if args.command == "benchmark":
        _emit(_run_benchmark())
        return 0
    if args.command == "sandbox":
        payload = _read_stdin_json()
        path = payload.get("path")
        if not isinstance(path, str) or not path:
            _emit_error("path must be a string")
            return 2
        _emit(run_sandbox(Path(path), allow_execute=bool(payload.get("allow_execute", False)), timeout_seconds=int(payload.get("timeout", 15) or 15)))
        return 0
    if args.command == "search":
        payload = _read_stdin_json()
        query = payload.get("query")
        if not isinstance(query, str) or not query.strip():
            _emit_error("query must be a non-empty string")
            return 2
        try:
            results = search_marketplace_extensions(query, page_size=int(payload.get("limit", 25) or 25))
        except Exception as exc:  # noqa: BLE001 - surface any registry/network failure to the caller
            _emit_error(f"Marketplace search failed: {exc}")
            return 0
        _emit({"results": results})
        return 0
    if args.command == "rules":
        _emit(rules_json())
        return 0
    return 2


def _run_sandboxes(paths: list[str], allow_execute: bool, timeout: int) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "schema_version": "0.1.0",
        "mode": "executed" if allow_execute else "plan-only",
        "extensions": {},
        "runs": [],
    }
    for item in paths:
        result = run_sandbox(Path(item), allow_execute=allow_execute, timeout_seconds=timeout)
        merged["runs"].append({
            "path": item,
            "mode": result.get("mode"),
            "plan": result.get("plan"),
        })
        for extension_id, observations in (result.get("extensions") or {}).items():
            merged["extensions"].setdefault(extension_id, []).extend(observations)
    return merged


def _write_previous_report(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    temp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False)
    with temp:
        json.dump(value, temp)
    return temp.name


def _read_stdin_json() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True))


def _emit_error(message: str) -> None:
    _emit({"error": message})


if __name__ == "__main__":
    raise SystemExit(main())
