from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .report_reader import read_report, report_view

SCHEMA = "guardrails.report-attestation.v1"


def create_attestation(report_path: str | Path) -> dict[str, Any]:
    path = Path(report_path)
    if not path.is_file():
        raise ValueError(f"Report does not exist: {path}")
    view = report_view(read_report(path))
    metadata = view.get("metadata") if isinstance(view.get("metadata"), dict) else {}
    return {"schema": SCHEMA, "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "report": {"filename": path.name, "sha256": _sha256(path), "bytes": path.stat().st_size, "scan_id": metadata.get("scan_id") or view.get("scan_id"), "scanner_build": metadata.get("scanner_build"), "ruleset_version": metadata.get("ruleset_version")}, "signature": None, "note": "Digest attestation only. It proves file identity, not signer identity."}


def verify_attestation(report_path: str | Path, attestation_path: str | Path) -> tuple[bool, str]:
    try:
        attestation = json.loads(Path(attestation_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"Could not read attestation: {exc}"
    if not isinstance(attestation, dict) or attestation.get("schema") != SCHEMA:
        return False, "Attestation schema is unsupported."
    report = attestation.get("report") if isinstance(attestation.get("report"), dict) else {}
    actual = _sha256(Path(report_path)) if Path(report_path).is_file() else ""
    if actual != report.get("sha256"):
        return False, "Report SHA-256 does not match the attestation."
    return True, "Report SHA-256 matches the digest attestation."


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
