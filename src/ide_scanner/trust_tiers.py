"""Trust-tier derivation: calm, factual, evidence-linked tier vocabulary.

Tiers replace judgment-heavy verdicts ("Do not install") in public surfaces:

- ``verified``       behavioral run completed and matched the declaration
- ``analyzed``       analysis completed; capabilities documented in the report
- ``attention``      undeclared capabilities or unexplained findings were flagged
- ``confirmed_risk`` authoritative threat evidence matched this exact artifact
- ``unanalyzed``     analysis did not complete for this artifact

The red tier is reserved for authoritative evidence only. Static suspicion,
even high-specificity abuse paths, stays in ``attention`` where teams decide
via policy instead of GuardRails editorializing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .classification_policy import finding_actionability

TRUST_TIER_VERSION = "1.0.0"

TrustTier = str  # one of TIERS

VERIFIED = "verified"
ANALYZED = "analyzed"
ATTENTION = "attention"
CONFIRMED_RISK = "confirmed_risk"
UNANALYZED = "unanalyzed"

TIERS = (VERIFIED, ANALYZED, ATTENTION, CONFIRMED_RISK, UNANALYZED)

_LABELS = {
    VERIFIED: "Verified \u00b7 behavior matches declaration",
    ANALYZED: "Analyzed \u00b7 capabilities documented",
    CONFIRMED_RISK: "Confirmed risk",
    UNANALYZED: "Analysis pending",
}

_EXPLAINABLE_CLASSES = {"capability", "reputation", "weak"}


@dataclass(frozen=True)
class TrustTierAssessment:
    tier: TrustTier
    label: str
    summary: str
    reason: str


def derive_trust_tier(extension: Any) -> TrustTierAssessment:
    """Derive the public trust tier for a finalized ExtensionReport."""
    decision = str(getattr(extension, "decision", "") or "incomplete")
    verdict = str(getattr(extension, "verdict", "") or "")
    analysis_status = str(getattr(extension, "analysis_status", "") or "incomplete")
    coverage = getattr(extension, "analysis_coverage", None) or {}
    coverage_complete = str(coverage.get("status") or "") == "complete"
    behavioral = _behavioral_verification(extension)

    if decision == "incomplete" or analysis_status != "complete":
        return TrustTierAssessment(
            tier=UNANALYZED,
            label=_LABELS[UNANALYZED],
            summary="Analysis has not completed for this exact version.",
            reason="incomplete_analysis",
        )

    if verdict == "malicious":
        return TrustTierAssessment(
            tier=CONFIRMED_RISK,
            label=_LABELS[CONFIRMED_RISK],
            summary=(
                "Authoritative threat evidence matched this exact artifact. "
                "See the linked evidence for the matching record."
            ),
            reason="authoritative_threat_evidence",
        )

    undeclared = _undeclared_capabilities(extension)
    unexplained = _unexplained_review_findings(extension)
    eligible_for_verified = (
        coverage_complete
        and behavioral is True
        and not undeclared
        and not unexplained
        and decision in {"allow", "review"}
    )

    if eligible_for_verified:
        return TrustTierAssessment(
            tier=VERIFIED,
            label=_LABELS[VERIFIED],
            summary="Observed behavior matches the declared capabilities.",
            reason="behavioral_verification_matched",
        )

    if decision == "block" or verdict == "suspicious" or undeclared or unexplained:
        if undeclared:
            count = len(undeclared)
            noun = "capability" if count == 1 else "capabilities"
            label = f"{count} undeclared {noun} detected"
            reason = "undeclared_capabilities:" + ",".join(undeclared)
        else:
            label = "Needs attention \u00b7 see findings"
            reason = "unexplained_or_preventive_evidence"
        return TrustTierAssessment(
            tier=ATTENTION,
            label=label,
            summary=(
                "Flagged behavior differs from the extension's declaration. "
                "Each flag links to the underlying evidence."
            ),
            reason=reason,
        )

    return TrustTierAssessment(
        tier=ANALYZED,
        label=_LABELS[ANALYZED],
        summary="Analysis completed for this exact version. Capabilities are documented in the report.",
        reason="analysis_completed_no_flags",
    )


def _behavioral_verification(extension: Any) -> bool | None:
    assessment = getattr(extension, "capability_assessment", None) or {}
    behavioral = assessment.get("behavioral_verification")
    if not isinstance(behavioral, dict):
        return None
    if str(behavioral.get("status") or "") != "complete":
        return False
    return bool(behavioral.get("matches_declaration"))


def _assessed_capabilities(extension: Any) -> dict[str, Any]:
    assessment = getattr(extension, "capability_assessment", None) or {}
    return assessment if isinstance(assessment, dict) and assessment else {}


def _undeclared_capabilities(extension: Any) -> list[str]:
    assessed = _assessed_capabilities(extension)
    unexpected = assessed.get("unexpected")
    if isinstance(unexpected, list):
        return sorted(str(item) for item in unexpected if item)

    # Pre-assessment fallback: compare observed capabilities against the
    # publisher profile when one exists so derivation works standalone.
    from .public_outcomes import EXPECTED_CAPABILITY_PROFILES

    profile = EXPECTED_CAPABILITY_PROFILES.get(str(getattr(extension, "extension_id", "")).lower())
    if not profile:
        return []
    observed = {
        str(item.get("id"))
        for item in (getattr(extension, "capabilities", None) or [])
        if isinstance(item, dict) and item.get("id")
    }
    return sorted(observed - set(profile["capabilities"]))


def _unexplained_review_findings(extension: Any) -> list[str]:
    assessed = _assessed_capabilities(extension)
    unexplained = assessed.get("unexplained_findings")
    if isinstance(unexplained, list):
        return sorted(str(item) for item in unexplained if item)

    return sorted(
        str(getattr(finding, "rule_id", ""))
        for finding in (getattr(extension, "findings", None) or [])
        if finding_actionability(finding) == "review"
        and _evidence_class(finding) not in _EXPLAINABLE_CLASSES
    )


def _evidence_class(finding: Any) -> str:
    evidence = getattr(finding, "evidence", None)
    if isinstance(evidence, dict) and isinstance(evidence.get("evidence_class"), str):
        return str(evidence["evidence_class"])
    return "weak"
