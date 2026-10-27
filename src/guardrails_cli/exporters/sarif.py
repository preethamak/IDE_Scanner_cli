from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ._atomic import write_text


SARIF_VERSION = "2.1.0"


def export_sarif(report: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    write_text(path, json.dumps(to_sarif(report), indent=2, sort_keys=True) + "\n")
    return path


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    extensions = [item for item in report.get("extensions", []) if isinstance(item, dict)]
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for extension in extensions:
        extension_id = str(extension.get("extension_id") or "unknown")
        version = str(extension.get("version") or "unknown")
        artifact = _artifact_hash(extension)
        for finding in [item for item in extension.get("findings", []) if isinstance(item, dict)]:
            rule_id = str(finding.get("rule_id") or "guardrails.unknown")
            severity = str(finding.get("severity") or extension.get("severity") or "medium").lower()
            rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": str(finding.get("title") or rule_id)}, "properties": {"security-severity": str(_score(severity)), "guardrails_evidence_class": str(finding.get("evidence_class") or "unknown")}})
            result = {"ruleId": rule_id, "level": _level(severity), "message": {"text": str(finding.get("evidence_summary") or finding.get("message") or "GuardRails finding.")}, "properties": {"extension_id": extension_id, "version": version, "artifact_sha256": artifact, "decision": str(extension.get("decision") or "incomplete"), "evidence_class": str(finding.get("evidence_class") or "unknown")}, "locations": [{"logicalLocations": [{"name": f"{extension_id}@{version}", "kind": "module"}]}]}
            results.append(result)
        if not extension.get("findings") and str(extension.get("decision") or "").lower() in {"block", "incomplete"}:
            rule_id = f"guardrails.{str(extension.get('decision')).lower()}"
            rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": "GuardRails release decision"}})
            results.append({"ruleId": rule_id, "level": "error" if extension.get("decision") == "block" else "warning", "message": {"text": str(extension.get("decision_reason") or "GuardRails requires review of this exact release.")}, "properties": {"extension_id": extension_id, "version": version, "artifact_sha256": artifact, "decision": extension.get("decision")}, "locations": [{"logicalLocations": [{"name": f"{extension_id}@{version}", "kind": "module"}]}]})
    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": SARIF_VERSION, "runs": [{"tool": {"driver": {"name": "GuardRails", "informationUri": "https://abscissa.dev", "rules": sorted(rules.values(), key=lambda item: item["id"])}}, "results": results, "invocations": [{"executionSuccessful": True}], "properties": {"scan_id": metadata.get("scan_id") or report.get("scan_id"), "scanner_build": metadata.get("scanner_build"), "ruleset_version": metadata.get("ruleset_version")}}]}


def _artifact_hash(extension: dict[str, Any]) -> str | None:
    artifact = extension.get("artifact_identity") if isinstance(extension.get("artifact_identity"), dict) else {}
    value = extension.get("artifact_sha256") or artifact.get("sha256")
    return str(value) if value else None


def _level(severity: str) -> str:
    return "error" if severity in {"critical", "high"} else "warning" if severity in {"medium", "moderate"} else "note"


def _score(severity: str) -> float:
    return {"critical": 9.0, "high": 8.0, "medium": 5.0, "moderate": 5.0, "low": 2.0}.get(severity, 1.0)
