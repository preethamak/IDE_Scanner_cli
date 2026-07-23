from __future__ import annotations

from typing import Any


def finding_severity(finding: dict[str, Any]) -> str:
    """Return the policy-resolved severity used for user-facing presentation."""
    return str(finding.get("effective_severity") or finding.get("severity") or "INFO").upper()


def detector_severity(finding: dict[str, Any]) -> str:
    """Return the detector's raw severity retained for technical context."""
    return str(finding.get("severity") or "INFO").upper()


def severity_detail(finding: dict[str, Any]) -> str:
    effective = finding_severity(finding)
    raw = detector_severity(finding)
    return effective if raw == effective else f"{effective} (detector: {raw})"
