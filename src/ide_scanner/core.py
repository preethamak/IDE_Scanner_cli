from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

from .discovery import discover_from_path, discover_local_installations
from .scanner import scan_targets


@dataclass(frozen=True)
class ScanRequest:
    paths: list[Path | str] = field(default_factory=list)
    extension_ids: list[str] = field(default_factory=list)
    marketplace_scan_ids: list[str] = field(default_factory=list)
    include_fixtures: bool = False
    all_local: bool = False
    online: bool = False
    known_bad_hashes_file: Path | str | None = None
    threat_feed_file: Path | str | None = None
    sandbox_observations_file: Path | str | None = None
    previous_report_file: Path | str | None = None
    include_posture: bool = True


def build_inventory(paths: list[Path | str] | None = None, all_local: bool = False) -> dict[str, Any]:
    targets: list[dict[str, str]] = []
    for path in paths or []:
        targets.extend(discover_from_path(path))
    if all_local:
        targets.extend(discover_local_installations())

    deduped: dict[str, dict[str, str]] = {}
    for target in targets:
        deduped[target["path"]] = target

    extensions = sorted((_inventory_item(target) for target in deduped.values()), key=lambda item: item["path"])
    return {
        "total_extensions": len(extensions),
        "extensions": extensions,
    }


def run_scan(request: ScanRequest) -> dict[str, Any]:
    return scan_targets(
        paths=request.paths,
        extension_ids=request.extension_ids,
        marketplace_scan_ids=request.marketplace_scan_ids,
        include_fixtures=request.include_fixtures,
        all_local=request.all_local,
        online=request.online,
        known_bad_hashes_file=request.known_bad_hashes_file,
        threat_feed_file=request.threat_feed_file,
        sandbox_observations_file=request.sandbox_observations_file,
        previous_report_file=request.previous_report_file,
        include_posture=request.include_posture,
    )


def summarize_report(report: dict[str, Any], top_limit: int = 10) -> dict[str, Any]:
    extensions = list(report.get("extensions") or [])
    summary = dict(report.get("summary") or {})
    return {
        "summary": summary,
        "human_summary": list(report.get("human_summary") or []),
        "posture_summary": dict(report.get("posture_summary") or {}),
        "posture": list(report.get("posture") or []),
        "version_deltas": list(report.get("version_deltas") or []),
        "top_risk_extensions": top_risk_extensions(report, limit=top_limit),
        "action_counts": _action_counts(extensions),
        "finding_counts": _finding_counts(extensions),
    }


def top_risk_extensions(report: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    extensions = list(report.get("extensions") or [])
    ranked = sorted(
        extensions,
        key=lambda item: (
            _verdict_rank(str(item.get("verdict") or "")),
            _severity_rank(str(item.get("severity") or "")),
            int(item.get("malware_score") or 0),
            int(item.get("risk_score") or 0),
            str(item.get("extension_id") or ""),
        ),
        reverse=True,
    )
    return [_extension_summary(item) for item in ranked[: max(limit, 0)]]


def _extension_summary(extension: dict[str, Any]) -> dict[str, Any]:
    findings = list(extension.get("findings") or [])
    return {
        "instance_id": extension.get("instance_id"),
        "extension_id": extension.get("extension_id"),
        "name": extension.get("name"),
        "publisher": extension.get("publisher"),
        "version": extension.get("version"),
        "source": extension.get("source"),
        "install_path": extension.get("install_path"),
        "severity": extension.get("severity"),
        "verdict": extension.get("verdict"),
        "verdict_reason": extension.get("verdict_reason"),
        "malware_score": extension.get("malware_score"),
        "risk_score": extension.get("risk_score"),
        "score_details": dict(extension.get("score_details") or {}),
        "finding_count": len(findings),
        "top_findings": [_finding_summary(finding) for finding in findings[:5]],
    }


def _inventory_item(target: dict[str, str]) -> dict[str, Any]:
    path = Path(target["path"])
    manifest = _read_inventory_manifest(path)
    publisher = str(manifest.get("publisher") or "unknown")
    name = str(manifest.get("name") or path.stem)
    try:
        stat = path.stat()
        modified_at = stat.st_mtime
    except OSError:
        modified_at = None
    return {
        "type": target.get("type", "vscode"),
        "path": str(path),
        "extension_id": f"{publisher}.{name}",
        "name": name,
        "display_name": manifest.get("displayName") or name,
        "publisher": publisher,
        "version": str(manifest.get("version") or "unknown"),
        "description": str(manifest.get("description") or ""),
        "icon_path": _icon_path(path, manifest),
        "modified_at": modified_at,
    }


def _read_inventory_manifest(path: Path) -> dict[str, Any]:
    if path.suffix.lower() == ".vsix":
        return {}
    manifest_path = path / "package.json"
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _icon_path(path: Path, manifest: dict[str, Any]) -> str:
    icon = manifest.get("icon")
    if not isinstance(icon, str) or not icon.strip() or path.suffix.lower() == ".vsix":
        return ""
    icon_path = (path / icon).resolve()
    try:
        icon_path.relative_to(path.resolve())
    except ValueError:
        return ""
    if icon_path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".svg", ".webp"}:
        return ""
    return str(icon_path) if icon_path.exists() else ""


def _finding_summary(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": finding.get("finding_id"),
        "rule_id": finding.get("rule_id"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "evidence_summary": finding.get("evidence_summary"),
        "file_refs": list(finding.get("file_refs") or []),
        "recommendation": finding.get("recommendation") or "",
    }


def _action_counts(extensions: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "malicious": 0,
        "suspicious": 0,
        "review": 0,
        "clean": 0,
    }
    for extension in extensions:
        verdict = str(extension.get("verdict") or "")
        if verdict in counts:
            counts[verdict] += 1
    return counts


def _finding_counts(extensions: list[dict[str, Any]]) -> dict[str, Any]:
    by_rule: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for extension in extensions:
        for finding in extension.get("findings") or []:
            _increment(by_rule, str(finding.get("rule_id") or "unknown"))
            _increment(by_category, str(finding.get("category") or "unknown"))
            _increment(by_severity, str(finding.get("severity") or "unknown"))
    return {
        "by_rule": dict(sorted(by_rule.items(), key=lambda item: (-item[1], item[0]))),
        "by_category": dict(sorted(by_category.items(), key=lambda item: (-item[1], item[0]))),
        "by_severity": dict(sorted(by_severity.items(), key=lambda item: (-item[1], item[0]))),
    }


def _increment(counter: dict[str, int], key: str) -> None:
    counter[key] = counter.get(key, 0) + 1


def _verdict_rank(verdict: str) -> int:
    return {
        "malicious": 4,
        "suspicious": 3,
        "review": 2,
        "clean": 1,
    }.get(verdict, 0)


def _severity_rank(severity: str) -> int:
    return {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }.get(severity, 0)
