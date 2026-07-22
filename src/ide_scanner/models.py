from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Verdict = Literal["clean", "review", "suspicious", "malicious"]
VerdictState = Literal["safe", "safe_with_notes", "needs_review", "suspicious", "confirmed_malicious"]
Decision = Literal["allow", "review", "block", "incomplete"]
PublicOutcome = Literal["clear", "expected_capability", "investigate", "preventive_block", "confirmed_threat", "incomplete"]
Status = Literal["success", "warning", "failure", "skipped"]


@dataclass
class Finding:
    finding_id: str
    extension_id: str
    version: str
    rule_id: str
    category: str
    severity: Severity
    confidence: float
    score: int
    evidence_type: str
    evidence_summary: str
    file_refs: list[str] = field(default_factory=list)
    recommendation: str = ""
    evidence: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if data["evidence"] is None:
            data.pop("evidence")
        return data


@dataclass
class Recommendation:
    priority: Literal["low", "medium", "high", "critical"]
    title: str
    description: str
    action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExtensionReport:
    instance_id: str
    extension_id: str
    name: str
    publisher: str
    version: str
    description: str
    repository: str
    install_path: str
    source: str
    artifact_hash: str
    severity: Severity
    verdict: Verdict
    malware_authority: str
    verdict_reason: str
    malware_score: int
    risk_score: int
    score_details: dict[str, Any]
    capabilities: list[dict[str, Any]]
    artifact_inventory: dict[str, Any]
    findings: list[Finding]
    scanned_files: int
    dependencies: dict[str, str] = field(default_factory=dict)
    decision: Decision = "incomplete"
    decision_reason: str = "Analysis has not completed."
    public_outcome: PublicOutcome = "incomplete"
    decision_basis: str = "incomplete"
    evidence_confidence: str = "none"
    provenance: dict[str, Any] = field(default_factory=dict)
    capability_assessment: dict[str, Any] = field(default_factory=dict)
    score_schema_version: str = "2"
    artifact_identity: dict[str, Any] = field(default_factory=dict)
    analysis_coverage: dict[str, Any] = field(default_factory=dict)
    baseline_diff: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["artifact_inventory"] = dict(self.artifact_inventory)
        file_inventory = data["artifact_inventory"].pop("_all_file_hashes", None)
        if isinstance(file_inventory, list):
            data["artifact_inventory"]["files"] = file_inventory
        data["findings"] = [finding.to_dict() for finding in self.findings]
        return data


@dataclass
class ReportMetadata:
    schema_version: str
    scan_id: str
    created_at: str
    scanner_version: str
    ruleset_version: str
    profile: str
    source: str
    total_extensions: int
    completed_extensions: int
    incomplete_extensions: int
    # A ruleset name alone is not enough to reproduce a decision: scanner
    # implementation changes can alter classification without adding a rule.
    scanner_build: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExtensionSummary:
    extension_id: str
    name: str
    publisher: str
    version: str
    source: str
    verdict: Verdict
    severity: Severity
    risk_score: int
    malware_score: int
    context_score: int
    grade: str
    verdict_state: VerdictState
    verdict_label: str
    top_findings: list[str]
    finding_count: int
    dependency_count: int
    activation_summary: str
    detail_ref: str
    icon_ref: str = ""
    from_cache: bool = False
    scan_incomplete: bool = False
    skipped_reason: str = ""
    decision: Decision = "incomplete"
    decision_reason: str = "Analysis has not completed."
    public_outcome: PublicOutcome = "incomplete"
    decision_basis: str = "incomplete"
    evidence_confidence: str = "none"
    provenance: dict[str, Any] = field(default_factory=dict)
    capability_assessment: dict[str, Any] = field(default_factory=dict)
    score_schema_version: str = "2"
    artifact_sha256: str = ""
    coverage_percent: int = 0
    baseline_changed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExtensionDetail:
    extension_id: str
    name: str
    publisher: str
    version: str
    description: str
    repository: str
    source: str
    verdict: Verdict
    severity: Severity
    risk_score: int
    malware_score: int
    context_score: int
    grade: str
    verdict_state: VerdictState
    verdict_label: str
    score_details: dict[str, Any]
    score_explanation: list[str]
    verdict_reason: str
    recommendations: list[Recommendation]
    findings: list[dict[str, Any]]
    evidence: dict[str, Any]
    manifest: dict[str, Any]
    dependencies: dict[str, str]
    dependency_inventory: list[dict[str, Any]]
    artifact_inventory: dict[str, Any]
    security_dimensions: dict[str, Any]
    capabilities: dict[str, Any]
    from_cache: bool = False
    scan_incomplete: bool = False
    skipped_reason: str = ""
    decision: Decision = "incomplete"
    decision_reason: str = "Analysis has not completed."
    public_outcome: PublicOutcome = "incomplete"
    decision_basis: str = "incomplete"
    evidence_confidence: str = "none"
    provenance: dict[str, Any] = field(default_factory=dict)
    capability_assessment: dict[str, Any] = field(default_factory=dict)
    score_schema_version: str = "2"
    artifact_identity: dict[str, Any] = field(default_factory=dict)
    analysis_coverage: dict[str, Any] = field(default_factory=dict)
    baseline_diff: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["recommendations"] = [item.to_dict() if isinstance(item, Recommendation) else item for item in self.recommendations]
        return data


@dataclass
class RuleMetadata:
    rule_id: str
    title: str
    category: str
    evidence_class: str
    default_severity: Severity
    description: str
    recommendation: str
    false_positive_notes: str = ""
    benchmark_tags: list[str] = field(default_factory=list)
    engine: str = "native-static"
    decision_effect: str = "review-context"
    confidence_basis: str = "Single deterministic static indicator; requires surrounding context."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReportBundleManifest:
    metadata: ReportMetadata
    summary_ref: str = "summary.json"
    leaderboard_ref: str = "leaderboard.json"
    posture_ref: str = "posture.json"
    rules_ref: str = "rules.json"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["metadata"] = self.metadata.to_dict()
        return data


@dataclass
class BenchmarkBundle:
    metadata: dict[str, Any]
    leaderboard: dict[str, Any]
    benchmark_summary: dict[str, Any]
    rule_coverage: dict[str, Any]
    comparisons: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PostureMetric:
    id: str
    status: Status
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    client: str = "system"
    category: str = "posture"
    score: int = 0
    weight: float = 1.0
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
