from __future__ import annotations

import copy
import json
import os
import re
import tempfile
import zipfile
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Any

from guardrails_cli import __version__

from ide_scanner.discovery import discover_from_path, discover_local_installations
from ide_scanner.registry import search_marketplace_extensions
from ide_scanner.report_bundle import build_report_bundle
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


def engine_identity() -> dict[str, str]:
    package = None
    for distribution_name in ("guardlens", "ide-scanner"):
        try:
            package = distribution(distribution_name)
            break
        except PackageNotFoundError:
            continue
    if package is None:
        return {"version": "unknown", "build": "unknown"}
    build = f"pypi:{package.version}"
    direct_url = package.read_text("direct_url.json")
    if direct_url:
        try:
            parsed = json.loads(direct_url)
            commit_id = (parsed.get("vcs_info") or {}).get("commit_id")
            if commit_id:
                build = str(commit_id)
        except json.JSONDecodeError:
            pass
    return {"version": str(package.version or "unknown"), "build": build}


def write_bundle(report: dict[str, Any], output: str | Path, *, source: str = "cli", profile: str = "standard") -> dict[str, Any]:
    bundle_report = copy.deepcopy(report)
    if source == "installed":
        for extension in bundle_report.get("extensions", []):
            if isinstance(extension, dict) and extension.get("client"):
                extension["source"] = str(extension["client"])
    bundle = build_report_bundle(bundle_report, profile=profile, source=source)
    engine = engine_identity()
    bundle["metadata"].update({
        "scanner_version": engine["version"],
        "scanner_build": os.environ.get("IDE_SCANNER_BUILD_SHA", "").strip() or engine["build"],
        "cli_version": __version__,
    })
    rows: list[dict[str, Any]] = []
    details: dict[str, dict[str, Any]] = {}
    occurrences: dict[tuple[str, str, str], int] = {}
    for extension in bundle_report.get("extensions", []):
        if not isinstance(extension, dict):
            continue
        partial_report = {**bundle_report, "extensions": [extension]}
        partial = build_report_bundle(partial_report, profile=profile, source=source)
        partial_rows = partial.get("leaderboard", {}).get("extensions", [])
        if not partial_rows:
            continue
        row = dict(partial_rows[0])
        old_ref = str(row.get("detail_ref") or "")
        detail = dict(partial.get("extensions", {}).get(old_ref) or {})
        client = str(extension.get("client") or extension.get("source") or "local")
        identity = (str(row.get("extension_id") or "unknown"), str(row.get("version") or "unknown"), client)
        occurrences[identity] = occurrences.get(identity, 0) + 1
        installation_id = f"{_safe_token(client)}:{identity[0]}@{identity[1]}:{occurrences[identity]}"
        stem = Path(old_ref).stem or f"{_safe_token(identity[0])}@{_safe_token(identity[1])}"
        detail_ref = f"extensions/{stem}--{_safe_token(client)}-{occurrences[identity]}.json"
        row.update({"source": client, "installation_id": installation_id, "detail_ref": detail_ref})
        detail.update({"source": client, "installation_id": installation_id})
        rows.append(row)
        details[detail_ref] = detail

    rows.sort(key=_bundle_priority, reverse=True)
    bundle["leaderboard"] = {"extensions": rows}
    bundle["extensions"] = details
    summary = bundle.get("summary") if isinstance(bundle.get("summary"), dict) else {}
    summary["top_risk_extensions"] = rows[:10]

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent, delete=False) as handle:
            temporary = Path(handle.name)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            _write_json(archive, "metadata.json", bundle["metadata"])
            _write_json(archive, "summary.json", bundle["summary"])
            _write_json(archive, "leaderboard.json", bundle["leaderboard"])
            _write_json(archive, "posture.json", bundle["posture"])
            _write_json(archive, "rules.json", bundle["rules"])
            for ref, detail in sorted(details.items()):
                _write_json(archive, ref, detail)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, output_path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {"output": str(output_path), "metadata": bundle["metadata"], "summary": summary.get("summary", {})}


def _safe_token(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.").lower() or "unknown"


def _bundle_priority(row: dict[str, Any]) -> tuple[int, int, int, str, str]:
    decision = str(row.get("decision") or "incomplete")
    return (
        {"allow": 1, "review": 2, "incomplete": 3, "block": 4}.get(decision, 3),
        int(row.get("malware_score") or 0),
        int(row.get("risk_score") or 0),
        str(row.get("extension_id") or ""),
        str(row.get("installation_id") or ""),
    )


def _write_json(archive: zipfile.ZipFile, name: str, value: object) -> None:
    archive.writestr(name, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8"))


def display_report(report: dict[str, Any], *, source: str = "cli", profile: str = "standard") -> dict[str, Any]:
    """Prepare raw scanner output for presentation without rebuilding evidence."""
    extensions = [item for item in report.get("extensions", []) if isinstance(item, dict)]
    summary = dict(report.get("summary") or {})
    engine = engine_identity()
    return {
        "scan_id": report.get("scan_id", "unknown"),
        "created_at": report.get("created_at", ""),
        "metadata": {
            "scan_id": report.get("scan_id", "unknown"),
            "created_at": report.get("created_at", ""),
            "scanner_version": engine["version"],
            "scanner_build": os.environ.get("IDE_SCANNER_BUILD_SHA", "").strip() or engine["build"],
            "cli_version": __version__,
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
