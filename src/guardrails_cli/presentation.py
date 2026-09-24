from __future__ import annotations

from typing import Any


ACTIONABILITY_RANK = {"block": 4, "review": 3, "low": 2, "contextual": 1}
_ACTIONABILITY_ALIASES = {
    "investigate": "review",
    "warning": "low",
    "note": "contextual",
    "observation": "contextual",
}


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


def finding_actionability(finding: dict[str, Any]) -> str:
    """Return the canonical actionability used by user-facing report views.

    New scanner reports carry this field directly. The fallback keeps older
    reports readable without treating a capability-only observation as a
    review-worthy finding.
    """
    value = str(finding.get("actionability") or "").lower()
    value = _ACTIONABILITY_ALIASES.get(value, value)
    if value in ACTIONABILITY_RANK:
        return value

    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    evidence_class = str(finding.get("evidence_class") or evidence.get("evidence_class") or "").lower()
    rule_id = str(finding.get("rule_id") or "")
    if evidence_class == "confirmed":
        return "block"
    if evidence_class in {"correlated", "observed", "dependency", "provenance", "exposure"}:
        return "review"
    if evidence_class == "capability":
        return "contextual"
    if evidence_class == "posture":
        return "review" if rule_id in {"entrypoint-ast-unparsed", "executable-heavy-obfuscation"} else "low"
    # Legacy reports sometimes used a detector-specific class such as
    # ``static-code``. Preserve visibility rather than silently discarding a
    # potentially meaningful signal when no policy field was serialized.
    if evidence_class or str(finding.get("severity") or "").upper() in {"HIGH", "CRITICAL"}:
        return "review"
    return "contextual"


def rank_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank findings by decision relevance before detector severity."""
    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    def confidence(value: object) -> float:
        try:
            return float(value or 0)
        except (TypeError, ValueError):
            return {"low": 0.3, "medium": 0.6, "high": 0.9}.get(str(value).lower(), 0)

    return sorted(
        findings,
        key=lambda item: (
            ACTIONABILITY_RANK[finding_actionability(item)],
            severity_rank.get(finding_severity(item), 0),
            confidence(item.get("confidence")),
            str(item.get("rule_id") or ""),
        ),
        reverse=True,
    )


def split_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Separate action-level evidence from context-only observations."""
    actionable = [item for item in findings if finding_actionability(item) != "contextual"]
    contextual = [item for item in findings if finding_actionability(item) == "contextual"]
    return rank_findings(actionable), rank_findings(contextual)
