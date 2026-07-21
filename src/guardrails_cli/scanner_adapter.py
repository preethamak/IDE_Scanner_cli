from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

from guardrails_cli import __version__

from ide_scanner.discovery import discover_from_path, discover_local_installations
from ide_scanner.registry import search_marketplace_extensions
from ide_scanner.report_bundle import write_report_bundle
from ide_scanner.rule_registry import rules_json
from ide_scanner.scanner import scan_targets


def search_extensions(query: str, *, limit: int = 20) -> list[dict[str, Any]]:
    return search_marketplace_extensions(query, page_size=limit)


def installed_extensions() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for target in discover_local_installations():
        path = Path(target["path"])
        manifest = _read_manifest(path / "package.json")
        publisher = str(manifest.get("publisher") or "unknown")
        name = str(manifest.get("name") or path.name)
        rows.append({
            "type": target.get("type", "vscode"),
            "path": str(path),
            "client": _client_from_path(path),
            "extension_id": f"{publisher}.{name}",
            "display_name": str(manifest.get("displayName") or name),
            "name": name,
            "publisher": publisher,
            "version": str(manifest.get("version") or "unknown"),
            "description": str(manifest.get("description") or ""),
        })
    return sorted(rows, key=lambda item: (item["client"], item["display_name"].lower(), item["version"]))


def scan_marketplace(extension_id: str, *, version: str | None = None) -> dict[str, Any]:
    return scan_targets(
        marketplace_scan_ids=[extension_id],
        marketplace_version=version,
        online=True,
        include_posture=False,
    )


def scan_paths(paths: list[str | Path], *, online: bool = False) -> dict[str, Any]:
    return scan_targets(paths=[Path(item) for item in paths], online=online, include_posture=False)


def discover_paths(path: str | Path) -> list[dict[str, str]]:
    return discover_from_path(path)


def get_rules() -> dict[str, Any]:
    return rules_json()


def write_bundle(report: dict[str, Any], output: str | Path, *, source: str = "cli", profile: str = "standard") -> dict[str, Any]:
    bundle_report = copy.deepcopy(report)
    if source == "installed":
        for extension in bundle_report.get("extensions", []):
            if isinstance(extension, dict) and extension.get("client"):
                extension["source"] = str(extension["client"])
    return write_report_bundle(bundle_report, output, profile=profile, source=source)


def display_report(report: dict[str, Any], *, source: str = "cli", profile: str = "standard") -> dict[str, Any]:
    """Prepare raw scanner output for presentation without rebuilding evidence."""
    extensions = [item for item in report.get("extensions", []) if isinstance(item, dict)]
    summary = dict(report.get("summary") or {})
    return {
        "scan_id": report.get("scan_id", "unknown"),
        "created_at": report.get("created_at", ""),
        "metadata": {
            "scan_id": report.get("scan_id", "unknown"),
            "created_at": report.get("created_at", ""),
            "scanner_version": __version__,
            "scanner_build": os.environ.get("IDE_SCANNER_BUILD_SHA", "").strip() or "unknown-local-build",
            "ruleset_version": rules_json().get("ruleset_version", "unknown"),
            "profile": profile,
            "source": source,
        },
        "summary": {**summary, "total_extensions": summary.get("total_extensions", len(extensions))},
        "extensions": extensions,
    }


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _client_from_path(path: Path) -> str:
    text = str(path).lower()
    if ".cursor" in text:
        return "Cursor"
    if ".windsurf" in text:
        return "Windsurf"
    if ".vscodium" in text:
        return "VSCodium"
    if ".vscode-insiders" in text:
        return "VS Code Insiders"
    return "VS Code"
