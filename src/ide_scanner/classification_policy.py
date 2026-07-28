from __future__ import annotations

from typing import Any, Literal

from .models import Finding

POLICY_VERSION = "3.0.0-calibration.3"

FindingActionability = Literal["contextual", "low", "review", "block"]


# These are sensitive product surfaces, not evidence that the surface is used
# unsafely. Source-to-sink and trust-boundary rules remain reviewable below.
_CONTEXTUAL_EXPOSURE_RULES = {
    "credential-command-execution",
    "credential-command-registration",
    "credential-config-key",
    "credential-global-state-key",
    "credential-inputbox-prompt",
}

_LOW_EXPOSURE_RULES = {
    # A verified write of credential-like material to broadly readable editor
    # configuration/state is a concrete hardening issue, but not by itself an
    # abuse path requiring approval review.
    "credential-config-update",
    "credential-global-state-storage",
}

_LOW_CAPABILITY_RULES = {
    "webview-csp-missing",
    "webview-csp-unsafe-directive",
}

_LOW_DEPENDENCY_RULES = {
    "mutable-dependency-source",
    "unpinned-dependency",
}

_LOW_PROVENANCE_RULES = {
    "repo-binary-artifacts",
}

_CONTEXTUAL_PROVENANCE_RULES = {
    # Presence of an archive/JAR/ASAR describes packaging. An origin mismatch,
    # unexplained source diff, or unattributed executable is handled by a
    # separate provenance rule and may still require review.
    "packed-artifact",
}

_REVIEW_POSTURE_RULES = {
    "entrypoint-ast-unparsed",
}


def finding_actionability(finding: Any) -> FindingActionability:
    evidence_class = finding_evidence_class(finding)
    rule_id = str(getattr(finding, "rule_id", ""))

    if evidence_class == "confirmed":
        return "block"
    if evidence_class == "vulnerability":
        return "block" if str(_evidence(finding).get("policy_action") or "review") == "block" else "review"
    if evidence_class in {"correlated", "observed"}:
        return "review"
    if evidence_class == "dependency":
        if rule_id == "vulnerable-npm-dependency" and not bool(_evidence(finding).get("exact")):
            return "contextual"
        if rule_id in _LOW_DEPENDENCY_RULES:
            return "low"
        return "review"
    if evidence_class == "provenance":
        if rule_id in _CONTEXTUAL_PROVENANCE_RULES:
            return "contextual"
        if rule_id in _LOW_PROVENANCE_RULES:
            return "low"
        # An executable binary without attributable origin requires a human,
        # but it is a low-severity provenance gap rather than suspicious code.
        if rule_id == "binary-without-origin":
            return "review"
        return "review"
    if evidence_class == "posture":
        return "review" if rule_id in _REVIEW_POSTURE_RULES else "low"
    if evidence_class == "exposure":
        if rule_id in _CONTEXTUAL_EXPOSURE_RULES:
            return "contextual"
        if rule_id in _LOW_EXPOSURE_RULES:
            return "low"
        return "review"
    if evidence_class == "capability":
        return "low" if rule_id in _LOW_CAPABILITY_RULES else "contextual"
    return "contextual"


def effective_finding_severity(finding: Any) -> str:
    actionability = finding_actionability(finding)
    if actionability == "contextual":
        return "INFO"
    if actionability == "low":
        return "LOW"
    if str(getattr(finding, "rule_id", "")) == "binary-without-origin":
        return "LOW"
    return str(getattr(finding, "severity", "INFO"))


def finding_evidence_class(finding: Any) -> str:
    evidence = _evidence(finding)
    return str(evidence.get("evidence_class") or "weak")


def is_review_relevant(finding: Finding) -> bool:
    return finding_actionability(finding) in {"review", "block"}


def is_decision_relevant(finding: Finding) -> bool:
    return finding_actionability(finding) != "contextual"


def _evidence(finding: Any) -> dict[str, Any]:
    evidence = getattr(finding, "evidence", None)
    return evidence if isinstance(evidence, dict) else {}
