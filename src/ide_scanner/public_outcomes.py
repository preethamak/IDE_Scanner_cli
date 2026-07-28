from __future__ import annotations

from typing import Any

from .models import ExtensionReport


# These profiles explain intended power; they are not allowlists. A profile can
# only produce an expected-capability outcome when registry identity, repository
# ownership, artifact identity, and analysis coverage all agree and no
# unexplained decision-relevant evidence remains.
EXPECTED_CAPABILITY_PROFILES: dict[str, dict[str, Any]] = {
    "dbaeumer.vscode-eslint": {
        "id": "vscode-eslint-v1",
        "publisher": "dbaeumer",
        "repository_owners": ["microsoft/vscode-eslint"],
        "capabilities": ["activation", "dynamic_code", "filesystem", "ide_contributions", "lifecycle_scripts", "process_execution"],
    },
    "eamodio.gitlens": {
        "id": "gitlens-v1",
        "publisher": "eamodio",
        "repository_owners": ["gitkraken/vscode-gitlens", "eamodio/vscode-gitlens"],
        "capabilities": ["activation", "credential_commands", "credential_configuration", "ide_contributions", "lifecycle_scripts", "process_execution"],
    },
    "ms-python.python": {
        "id": "vscode-python-v1",
        "publisher": "ms-python",
        "repository_owners": ["microsoft/vscode-python"],
        "capabilities": ["activation", "ide_contributions", "lifecycle_scripts", "native_code", "packed_artifacts", "process_execution"],
    },
    "rust-lang.rust-analyzer": {
        "id": "rust-analyzer-v1",
        "publisher": "rust-lang",
        "repository_owners": ["rust-lang/rust-analyzer"],
        "capabilities": ["activation", "ide_contributions", "native_code", "packed_artifacts", "process_execution"],
    },
    "semgrep.semgrep": {
        "id": "semgrep-vscode-v1",
        "publisher": "semgrep",
        "repository_owners": ["semgrep/semgrep-vscode"],
        "capabilities": ["activation", "ide_contributions", "lifecycle_scripts", "native_code", "packed_artifacts", "process_execution"],
    },
    "snyk-security.snyk-vulnerability-scanner": {
        "id": "snyk-vscode-v1",
        "publisher": "snyk-security",
        "repository_owners": ["snyk/vscode-extension"],
        "capabilities": ["activation", "credential_commands", "credential_configuration", "ide_contributions", "lifecycle_scripts", "native_code", "packed_artifacts", "process_execution"],
    },
    "sonarsource.sonarlint-vscode": {
        "id": "sonarqube-vscode-v1",
        "publisher": "sonarsource",
        "repository_owners": ["sonarsource/sonarlint-vscode"],
        "capabilities": ["activation", "ide_contributions", "lifecycle_scripts", "native_code", "packed_artifacts", "process_execution"],
    },
}

_PROVENANCE_CONFLICT_RULES = {
    "known-bad-artifact",
    "marketplace-extension-not-found",
    "marketplace-name-impersonation",
    "marketplace-removed-malware",
    "marketplace-removed-package",
    "source-vsix-diff-unexplained",
    "trusted-threat-feed-hit",
}
_EXPLAINABLE_CLASSES = {"capability", "reputation", "weak"}


def apply_public_assessment(extension: ExtensionReport) -> None:
    profile = EXPECTED_CAPABILITY_PROFILES.get(extension.extension_id.lower())
    rule_ids = {finding.rule_id for finding in extension.findings}
    evidence_classes = {_evidence_class(finding) for finding in extension.findings}
    capability_ids = sorted(
        str(item.get("id")) for item in extension.capabilities
        if isinstance(item, dict) and item.get("id")
    )
    verified = "marketplace-verified-publisher" in rule_ids
    conflicted = bool(rule_ids & _PROVENANCE_CONFLICT_RULES)
    repository = extension.repository.lower().rstrip("/")
    publisher_matches = bool(profile) and extension.publisher.lower() == str(profile["publisher"]).lower()
    repository_matches = bool(profile) and any(
        f"github.com/{owner.lower()}" in repository for owner in profile["repository_owners"]
    )
    coverage_complete = str(extension.analysis_coverage.get("status") or "") == "complete"
    artifact_consistent = (
        extension.artifact_identity.get("extension_id") == extension.extension_id
        and extension.artifact_identity.get("version") == extension.version
        and len(str(extension.artifact_identity.get("sha256") or "")) == 64
    )
    established = bool(
        profile and verified and publisher_matches and repository_matches
        and coverage_complete and artifact_consistent and not conflicted
    )
    provenance_tier = "conflicted" if conflicted else "established" if established else "verified" if verified else "unknown"
    expected = set(profile["capabilities"]) if profile else set()
    matched = sorted(set(capability_ids) & expected)
    unexpected_capabilities = sorted(set(capability_ids) - expected) if profile else capability_ids
    unexplained_findings = sorted(
        finding.rule_id for finding in extension.findings
        if _evidence_class(finding) not in _EXPLAINABLE_CLASSES
    )

    extension.provenance = {
        "tier": provenance_tier,
        "publisher_verified": verified,
        "publisher_matches_profile": publisher_matches,
        "repository_matches_profile": repository_matches,
        "artifact_identity_consistent": artifact_consistent,
        "profile_id": str(profile["id"]) if profile else "",
    }
    extension.capability_assessment = {
        "profile_id": str(profile["id"]) if profile else "",
        "observed": capability_ids,
        "matched": matched,
        "unexpected": unexpected_capabilities,
        "unexplained_findings": unexplained_findings,
    }

    if extension.decision == "incomplete":
        extension.public_outcome = "incomplete"
        extension.decision_basis = "incomplete_analysis"
        extension.evidence_confidence = "none"
    elif extension.verdict == "malicious":
        extension.public_outcome = "confirmed_threat"
        extension.decision_basis = "authoritative_threat_evidence"
        extension.evidence_confidence = "confirmed"
    elif extension.decision == "block":
        extension.public_outcome = "preventive_block"
        extension.decision_basis = "high_specificity_abuse_path"
        extension.evidence_confidence = "high"
    elif (
        extension.decision == "review"
        and established
        and not unexpected_capabilities
        and not unexplained_findings
        and evidence_classes <= _EXPLAINABLE_CLASSES
    ):
        extension.decision_reason = (
            "Review is capability-based: the observed powerful behavior matches "
            "the extension's established publisher and expected-capability profile."
        )
        extension.public_outcome = "expected_capability"
        extension.decision_basis = "established_expected_capability"
        extension.evidence_confidence = "contextual"
    elif extension.decision == "review":
        extension.public_outcome = "investigate"
        extension.decision_basis = "unexplained_or_unestablished_behavior"
        extension.evidence_confidence = str(extension.score_details.get("confidence") or "medium")
    else:
        extension.public_outcome = "clear"
        extension.decision_basis = "no_actionable_evidence"
        extension.evidence_confidence = "none"


def _evidence_class(finding: Any) -> str:
    evidence = getattr(finding, "evidence", None)
    if isinstance(evidence, dict) and isinstance(evidence.get("evidence_class"), str):
        return str(evidence["evidence_class"])
    return "weak"
