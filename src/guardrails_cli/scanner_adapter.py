from __future__ import annotations

import copy
import base64
import hashlib
import importlib.util
import json
import os
import re
import tempfile
import zipfile
from importlib.metadata import PackageNotFoundError, Distribution, distribution
from pathlib import Path
from typing import Any, Callable

from guardrails_cli import __version__


ENGINE_DISTRIBUTION = "guardlens-core"


def _engine_identity() -> dict[str, Any]:
    try:
        return json.loads(Path(__file__).with_name("engine_distribution.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError(f"Scanner distribution identity is unreadable: {exc}") from exc


def _engine_distribution() -> Distribution:
    try:
        return distribution(ENGINE_DISTRIBUTION)
    except PackageNotFoundError as exc:
        raise RuntimeError(
            "Guardrails requires the guardlens-core scanner distribution. Reinstall Guardrails before scanning."
        ) from exc


def _engine_root() -> Path:
    spec = importlib.util.find_spec("ide_scanner")
    if spec is None or spec.origin is None:
        raise RuntimeError("Installed guardlens-core scanner package is unavailable.")
    return Path(spec.origin).resolve().parent


def verify_engine_integrity(engine_root: Path | None = None) -> None:
    identity = _engine_identity()
    expected_version = identity.get("version")
    if not isinstance(expected_version, str) or not expected_version:
        raise RuntimeError("Scanner distribution identity contains no version.")
    package = _engine_distribution()
    if package.version != expected_version:
        raise RuntimeError(
            f"Guardrails requires guardlens-core {expected_version}, found {package.version}. Reinstall Guardrails."
        )
    root = engine_root or _engine_root()
    expected: dict[str, str] = {}
    for record in package.files or []:
        relative = Path(str(record))
        if not relative.parts or relative.parts[0] != "ide_scanner" or record.hash is None:
            continue
        engine_relative = relative.relative_to("ide_scanner").as_posix()
        if relative.suffix == ".pyc" or "__pycache__" in relative.parts:
            continue
        expected[engine_relative] = record.hash.value
    required = {"__init__.py", "scanner.py"}
    if not required.issubset(expected):
        raise RuntimeError("guardlens-core distribution does not contain a complete, hash-recorded scanner package.")
    actual_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.suffix != ".pyc" and "__pycache__" not in path.parts
    }
    if actual_files != set(expected):
        raise RuntimeError("guardlens-core scanner files do not match its installed distribution record.")
    for relative, expected_hash in sorted(expected.items()):
        target = root / relative
        try:
            actual_hash = base64.urlsafe_b64encode(hashlib.sha256(target.read_bytes()).digest()).decode().rstrip("=")
        except OSError as exc:
            raise RuntimeError(f"Installed scanner file is unavailable: {relative}") from exc
        if actual_hash != expected_hash:
            raise RuntimeError(
                f"Installed scanner integrity check failed for {relative}. "
                "Reinstall Guardrails before scanning."
            )


# Verify package bytes before importing any scanner module. An integrity guard
# that runs after import is too late because module-level code has already run.
verify_engine_integrity()

from ide_scanner.discovery import discover_from_path, discover_local_installations
from ide_scanner.providers import provider_diagnostics
from ide_scanner.registry import search_marketplace_extensions
from ide_scanner.report_bundle import build_report_bundle
from ide_scanner.rule_registry import rules_json
from ide_scanner.scanner import DEEP_REQUIRED_PROVIDERS, scan_targets


def analysis_provider_diagnostics(*, probe: bool = True) -> dict[str, dict[str, Any]]:
    verify_engine_integrity()
    return provider_diagnostics(probe=probe)


def search_extensions(query: str, *, limit: int = 20) -> list[dict[str, Any]]:
    verify_engine_integrity()
    return search_marketplace_extensions(query, page_size=limit)


def installed_extensions() -> list[dict[str, Any]]:
    verify_engine_integrity()
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


def scan_marketplace(
    extension_id: str,
    *,
    version: str | None = None,
    target_platform: str | None = None,
    registry_snapshot: str | Path | None = None,
    required_providers: set[str] | frozenset[str] | None = None,
) -> dict[str, Any]:
    verify_engine_integrity()
    return _run_engine_scan(
        lambda: scan_targets(
            marketplace_scan_ids=[extension_id],
            marketplace_version=version,
            marketplace_target_platform=target_platform,
            online=True,
            registry_snapshot_file=registry_snapshot,
            include_posture=False,
            required_providers=required_providers,
        )
    )


def scan_paths(
    paths: list[str | Path],
    *,
    online: bool = False,
    registry_snapshot: str | Path | None = None,
    required_providers: set[str] | frozenset[str] | None = None,
) -> dict[str, Any]:
    verify_engine_integrity()
    return _run_engine_scan(
        lambda: scan_targets(
            paths=[Path(item) for item in paths],
            online=online,
            registry_snapshot_file=registry_snapshot,
            include_posture=False,
            required_providers=required_providers,
        )
    )


def _run_engine_scan(operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    previous = os.environ.get("IDE_SCANNER_BUILD_SHA")
    os.environ["IDE_SCANNER_BUILD_SHA"] = engine_identity()["build"]
    try:
        return operation()
    finally:
        if previous is None:
            os.environ.pop("IDE_SCANNER_BUILD_SHA", None)
        else:
            os.environ["IDE_SCANNER_BUILD_SHA"] = previous


def discover_paths(path: str | Path) -> list[dict[str, str]]:
    verify_engine_integrity()
    return discover_from_path(path)


def get_rules() -> dict[str, Any]:
    verify_engine_integrity()
    return rules_json()


def engine_identity() -> dict[str, str]:
    package = _engine_distribution()
    return {"version": str(package.version), "build": f"pypi:{package.version}"}


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
    catalog = rules_json()
    return {
        "scan_id": report.get("scan_id", "unknown"),
        "created_at": report.get("created_at", ""),
        "metadata": {
            "scan_id": report.get("scan_id", "unknown"),
            "created_at": report.get("created_at", ""),
            "scanner_version": engine["version"],
            "scanner_build": os.environ.get("IDE_SCANNER_BUILD_SHA", "").strip() or engine["build"],
            "cli_version": __version__,
            "ruleset_version": report.get("ruleset_version") or catalog.get("ruleset_version", "unknown"),
            "policy_version": report.get("policy_version") or catalog.get("policy_version", "unknown"),
            "intelligence_snapshot": dict(report.get("intelligence") or {}),
            "profile": profile,
            "source": source,
        },
        "registry_checks": dict(report.get("registry_checks") or {}),
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
