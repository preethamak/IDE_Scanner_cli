from __future__ import annotations
from typing import Any


def compare_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    def index(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {str(item.get("extension_id") or "").lower(): item for item in report.get("extensions", []) if isinstance(item, dict) and item.get("extension_id")}
    left, right = index(before), index(after)
    rows = []
    for key in sorted(set(left) | set(right)):
        old, new = left.get(key), right.get(key)
        if not old: rows.append({"extension_id": new.get("extension_id"), "change": "added", "to": _summary(new)}); continue
        if not new: rows.append({"extension_id": old.get("extension_id"), "change": "removed", "from": _summary(old)}); continue
        changed = {field: [old.get(field), new.get(field)] for field in ("version", "decision", "severity", "coverage_percent", "artifact_sha256") if old.get(field) != new.get(field)}
        old_rules = {str(item.get("rule_id")) for item in old.get("findings", []) if isinstance(item, dict)}; new_rules = {str(item.get("rule_id")) for item in new.get("findings", []) if isinstance(item, dict)}
        if changed or old_rules != new_rules: rows.append({"extension_id": new.get("extension_id"), "change": "changed", "fields": changed, "added_rule_ids": sorted(new_rules - old_rules), "removed_rule_ids": sorted(old_rules - new_rules)})
    return {"schema": "guardrails.report-diff.v1", "changed": len(rows), "extensions": rows}


def _summary(item: dict[str, Any]) -> dict[str, Any]: return {field: item.get(field) for field in ("version", "decision", "severity", "coverage_percent", "artifact_sha256")}
