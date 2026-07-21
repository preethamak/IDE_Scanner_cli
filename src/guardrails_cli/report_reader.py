from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any


MAX_REPORT_BYTES = 512 * 1024 * 1024
MAX_JSON_ENTRY_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.I)


def read_report(path: str | Path) -> dict[str, Any]:
    report_path = Path(path)
    if not report_path.exists():
        raise ValueError(f"Report does not exist: {report_path}")
    if report_path.suffix.lower() == ".zip":
        return read_report_zip(report_path)
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read report JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Report JSON must contain an object at the top level.")
    return data


def read_report_zip(path: str | Path) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise ValueError("Report ZIP contains duplicate entry names.")
            total_size = sum(item.file_size for item in infos)
            if total_size > MAX_REPORT_BYTES:
                raise ValueError("Report ZIP expands beyond the supported size limit.")
            for item in infos:
                if item.filename.endswith(".json") and item.file_size > MAX_JSON_ENTRY_BYTES:
                    raise ValueError(f"Report entry is too large: {item.filename}")
            metadata = _read_json(archive, "metadata.json", required=True)
            summary = _read_json(archive, "summary.json", required=True)
            leaderboard = _read_json(archive, "leaderboard.json", required=True)
            posture = _read_json(archive, "posture.json")
            rules = _read_json(archive, "rules.json", required=True)
            details = {
                name: _read_json(archive, name, required=True)
                for name in names
                if name.startswith("extensions/") and name.endswith(".json")
            }
    except zipfile.BadZipFile as exc:
        raise ValueError("Report is not a valid ZIP archive.") from exc
    return {
        "metadata": metadata,
        "summary": summary,
        "leaderboard": leaderboard,
        "posture": posture,
        "rules": rules,
        "details": details,
    }


def report_view(data: dict[str, Any]) -> dict[str, Any]:
    """Return a presentation model without rebuilding canonical scanner data."""
    if "details" not in data:
        extensions = [item for item in data.get("extensions", []) if isinstance(item, dict)]
        return {
            **data,
            "summary": dict(data.get("summary") or {}),
            "extensions": extensions,
            "metadata": dict(data.get("metadata") or {}),
        }

    metadata = dict(data.get("metadata") or {})
    wrapped_summary = dict(data.get("summary") or {})
    summary = dict(wrapped_summary.get("summary") or wrapped_summary)
    leaderboard = dict(data.get("leaderboard") or {})
    rows = [item for item in leaderboard.get("extensions", []) if isinstance(item, dict)]
    details = data.get("details") if isinstance(data.get("details"), dict) else {}
    extensions: list[dict[str, Any]] = []
    for row in rows:
        detail_ref = str(row.get("detail_ref") or "")
        detail = details.get(detail_ref) if detail_ref else None
        merged = {**row, **(detail if isinstance(detail, dict) else {})}
        # Leaderboard identity and decision fields describe this exact row and
        # must not be replaced by a colliding or stale detail document.
        for key in (
            "extension_id", "version", "decision", "decision_reason",
            "public_outcome", "artifact_sha256", "coverage_percent",
            "severity", "risk_score", "malware_score", "detail_ref",
        ):
            if key in row:
                merged[key] = row[key]
        merged["detail_available"] = isinstance(detail, dict)
        extensions.append(merged)
    if not rows:
        extensions = [item for item in details.values() if isinstance(item, dict)]
    return {
        "scan_id": metadata.get("scan_id", "unknown"),
        "created_at": metadata.get("created_at", ""),
        "metadata": metadata,
        "summary": summary,
        "extensions": extensions,
        "rules": dict(data.get("rules") or {}),
        "posture": dict(data.get("posture") or {}),
    }


def validate_report(path: str | Path) -> tuple[bool, list[str]]:
    try:
        data = read_report(path)
    except ValueError as exc:
        return False, [str(exc)]
    errors = validate_report_data(data, zipped=Path(path).suffix.lower() == ".zip")
    return not errors, errors


def validate_report_data(data: dict[str, Any], *, zipped: bool = False) -> list[str]:
    errors: list[str] = []
    if zipped:
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        summary_wrapper = data.get("summary") if isinstance(data.get("summary"), dict) else {}
        summary = summary_wrapper.get("summary") if isinstance(summary_wrapper.get("summary"), dict) else {}
        leaderboard = data.get("leaderboard") if isinstance(data.get("leaderboard"), dict) else {}
        rows = leaderboard.get("extensions") if isinstance(leaderboard.get("extensions"), list) else []
        details = data.get("details") if isinstance(data.get("details"), dict) else {}
        rules = data.get("rules") if isinstance(data.get("rules"), dict) else {}
        for key in ("schema_version", "scan_id", "scanner_version", "ruleset_version", "total_extensions"):
            if metadata.get(key) in {None, ""}:
                errors.append(f"metadata.json is missing {key}")
        if not isinstance(rules.get("rules"), list):
            errors.append("rules.json is missing the rules list")
        declared = metadata.get("total_extensions")
        if isinstance(declared, int) and declared != len(rows):
            errors.append(f"metadata declares {declared} extensions but leaderboard contains {len(rows)}")
        summary_total = summary.get("total_extensions")
        if isinstance(summary_total, int) and summary_total != len(rows):
            errors.append(f"summary declares {summary_total} extensions but leaderboard contains {len(rows)}")
        detail_refs = [str(row.get("detail_ref") or "") for row in rows if isinstance(row, dict)]
        missing_refs = sorted({ref for ref in detail_refs if ref and ref not in details})
        if missing_refs:
            errors.append(f"leaderboard references {len(missing_refs)} missing extension detail file(s)")
        reused = len([ref for ref in detail_refs if ref]) - len({ref for ref in detail_refs if ref})
        if reused:
            errors.append(f"{reused} extension row(s) reuse another installation's detail reference")
        installation_ids = [str(row.get("installation_id") or "") for row in rows if isinstance(row, dict)]
        if any(installation_ids):
            if not all(installation_ids):
                errors.append("leaderboard mixes rows with and without installation IDs")
            elif len(installation_ids) != len(set(installation_ids)):
                errors.append("leaderboard contains duplicate installation IDs")
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                errors.append(f"leaderboard row {index + 1} is not an object")
                continue
            for key in ("extension_id", "version", "decision", "detail_ref"):
                if row.get(key) in {None, ""}:
                    errors.append(f"leaderboard row {index + 1} is missing {key}")
            decision = str(row.get("decision") or "")
            if decision and decision not in {"allow", "review", "block", "incomplete"}:
                errors.append(f"leaderboard row {index + 1} has invalid decision {decision}")
            sha = str(row.get("artifact_sha256") or "")
            if sha and not SHA256_RE.fullmatch(sha):
                errors.append(f"leaderboard row {index + 1} has an invalid artifact SHA-256")
            detail = details.get(str(row.get("detail_ref") or ""))
            if isinstance(detail, dict):
                if detail.get("extension_id") != row.get("extension_id") or detail.get("version") != row.get("version"):
                    errors.append(f"leaderboard row {index + 1} does not match its extension detail identity")
    else:
        extensions = data.get("extensions")
        if not isinstance(extensions, list):
            errors.append("report JSON is missing the extensions list")
        if not isinstance(data.get("summary"), dict):
            errors.append("report JSON is missing the summary object")
    return errors


def _read_json(archive: zipfile.ZipFile, name: str, *, required: bool = False) -> dict[str, Any]:
    try:
        raw = archive.read(name)
    except KeyError:
        if required:
            raise ValueError(f"Report is missing {name}") from None
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Report entry is not valid JSON: {name}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Report entry must contain an object: {name}")
    return data
