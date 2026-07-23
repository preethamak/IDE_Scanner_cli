from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import zipfile
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from .classification_policy import effective_finding_severity, finding_actionability, finding_evidence_class
from .jsonc import loads_jsonc
from .models import ExtensionDetail, ExtensionReport, ExtensionSummary, Recommendation, ReportMetadata
from .rule_registry import rules_json

SCHEMA_VERSION = "2.2"


def build_report_bundle(
    report: dict[str, Any],
    *,
    profile: str = "smart",
    source: str = "unknown",
    include_raw_evidence: bool = False,
) -> dict[str, Any]:
    extensions = [_extension_from_dict(item) for item in report.get("extensions") or [] if isinstance(item, dict)]
    metadata = _metadata(report, extensions, profile=profile, source=source)
    summaries = [_to_summary(extension) for extension in extensions]
    details = [
        _to_detail(
            extension,
            include_raw_evidence=include_raw_evidence,
            policy_version=metadata.policy_version,
        )
        for extension in extensions
    ]
    return {
        "metadata": metadata.to_dict(),
        "summary": _summary(report, extensions, summaries),
        "leaderboard": {"extensions": [summary.to_dict() for summary in _rank_summaries(summaries)]},
        "posture": {
            "posture_summary": report.get("posture_summary") or {},
            "posture": report.get("posture") or [],
        },
        "rules": rules_json(),
        "extensions": {
            summary.detail_ref: detail.to_dict()
            for summary, detail in zip(summaries, details, strict=True)
        },
    }


def write_report_bundle(
    report: dict[str, Any],
    output: Path | str,
    *,
    profile: str = "smart",
    source: str = "unknown",
    include_raw_evidence: bool = False,
) -> dict[str, Any]:
    bundle = build_report_bundle(
        report,
        profile=profile,
        source=source,
        include_raw_evidence=include_raw_evidence,
    )
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        _write_json(archive, "metadata.json", bundle["metadata"])
        _write_json(archive, "summary.json", bundle["summary"])
        _write_json(archive, "leaderboard.json", bundle["leaderboard"])
        _write_json(archive, "posture.json", bundle["posture"])
        _write_json(archive, "rules.json", bundle["rules"])
        for ref, detail in sorted(bundle["extensions"].items()):
            _write_json(archive, ref, detail)
    return {
        "output": str(output_path),
        "metadata": bundle["metadata"],
        "summary": bundle["summary"]["summary"],
    }


def iter_report_events(report: dict[str, Any], *, profile: str = "smart", source: str = "unknown", output: str = ""):
    bundle = build_report_bundle(report, profile=profile, source=source)
    metadata = bundle["metadata"]
    yield {
        "type": "scan_started",
        "scan_id": metadata["scan_id"],
        "profile": metadata["profile"],
        "source": metadata["source"],
        "total_extensions": metadata["total_extensions"],
    }
    for row in bundle["leaderboard"]["extensions"]:
        yield {
            "type": "extension_summary_ready",
            "scan_id": metadata["scan_id"],
            "extension_id": row["extension_id"],
            "risk_score": row["risk_score"],
            "malware_score": row["malware_score"],
            "context_score": row["context_score"],
            "verdict": row["verdict"],
            "verdict_state": row["verdict_state"],
            "verdict_label": row["verdict_label"],
            "decision": row["decision"],
            "decision_reason": row["decision_reason"],
            "coverage_percent": row["coverage_percent"],
            "severity": row["severity"],
            "grade": row["grade"],
            "detail_ref": row["detail_ref"],
        }
        yield {
            "type": "extension_detail_ready",
            "scan_id": metadata["scan_id"],
            "extension_id": row["extension_id"],
            "detail_ref": row["detail_ref"],
        }
    yield {
        "type": "scan_completed",
        "scan_id": metadata["scan_id"],
        "output": output,
        "completed_extensions": metadata["completed_extensions"],
        "incomplete_extensions": metadata["incomplete_extensions"],
    }


def _metadata(report: dict[str, Any], extensions: list[ExtensionReport], *, profile: str, source: str) -> ReportMetadata:
    created_at = str(report.get("created_at") or dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"))
    scan_id = str(report.get("scan_id") or f"scan_{dt.datetime.now(dt.UTC).strftime('%Y%m%d%H%M%S')}")
    incomplete = sum(1 for extension in extensions if _scan_incomplete(extension))
    return ReportMetadata(
        schema_version=SCHEMA_VERSION,
        scan_id=scan_id,
        created_at=created_at,
        scanner_version=_scanner_version(),
        ruleset_version=str(report.get("ruleset_version") or "legacy"),
        profile=profile,
        source=source,
        total_extensions=len(extensions),
        completed_extensions=len(extensions) - incomplete,
        incomplete_extensions=incomplete,
        scanner_build=str(report.get("scanner_build") or _scanner_build()),
        policy_version=str(report.get("policy_version") or "legacy"),
        intelligence_snapshot=dict(report.get("intelligence")) if isinstance(report.get("intelligence"), dict) else {},
    )


def _summary(
    report: dict[str, Any],
    extensions: list[ExtensionReport],
    summaries: list[ExtensionSummary],
) -> dict[str, Any]:
    verdict_counts = {verdict: 0 for verdict in ("clean", "review", "suspicious", "malicious")}
    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    finding_counts: dict[str, int] = {}
    evidence_class_counts: dict[str, int] = {}
    decision_counts = {decision: 0 for decision in ("block", "review", "incomplete", "allow")}
    for extension in extensions:
        decision_counts[extension.decision] = decision_counts.get(extension.decision, 0) + 1
        verdict_counts[extension.verdict] = verdict_counts.get(extension.verdict, 0) + 1
        severity_counts[extension.severity] = severity_counts.get(extension.severity, 0) + 1
        for finding in extension.findings:
            finding_counts[finding.rule_id] = finding_counts.get(finding.rule_id, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
            evidence_class = str((finding.evidence or {}).get("evidence_class") or "weak")
            evidence_class_counts[evidence_class] = evidence_class_counts.get(evidence_class, 0) + 1
    posture_summary = report.get("posture_summary") if isinstance(report.get("posture_summary"), dict) else {}
    return {
        "summary": {
            "total_extensions": len(extensions),
            "clean": verdict_counts.get("clean", 0),
            "review": verdict_counts.get("review", 0),
            "suspicious": verdict_counts.get("suspicious", 0),
            "malicious": verdict_counts.get("malicious", 0),
            "max_risk_score": max((extension.risk_score for extension in extensions), default=0),
            "max_malware_score": max((extension.malware_score for extension in extensions), default=0),
            "max_context_score": max((_context_score(extension) for extension in extensions), default=0),
            "posture_status": posture_summary.get("status", "skipped"),
            "decision_counts": decision_counts,
            "incomplete": decision_counts.get("incomplete", 0),
        },
        "top_risk_extensions": [summary.to_dict() for summary in _rank_summaries(summaries)[:10]],
        "finding_counts": _sorted_counts(finding_counts),
        "severity_counts": _sorted_counts(severity_counts),
        "category_counts": _sorted_counts(category_counts),
        "evidence_class_counts": _sorted_counts(evidence_class_counts),
        "version_deltas": list(report.get("version_deltas") or []),
    }


def _to_summary(extension: ExtensionReport) -> ExtensionSummary:
    return ExtensionSummary(
        extension_id=extension.extension_id,
        name=extension.name,
        publisher=extension.publisher,
        version=extension.version,
        source=extension.source,
        verdict=extension.verdict,
        severity=extension.severity,
        risk_score=extension.risk_score,
        malware_score=extension.malware_score,
        context_score=_context_score(extension),
        grade=grade_extension(extension.verdict, extension.risk_score, extension.malware_score, extension.findings),
        verdict_state=_verdict_state(extension),
        verdict_label=_verdict_label(extension),
        top_findings=[finding.rule_id for finding in _rank_findings(extension.findings)[:5]],
        finding_count=len(extension.findings),
        dependency_count=len(extension.dependencies),
        activation_summary=_activation_summary(extension),
        detail_ref=f"extensions/{_safe_detail_name(extension.extension_id, extension.version)}.json",
        icon_ref="",
        from_cache=bool(getattr(extension, "from_cache", False)),
        scan_incomplete=_scan_incomplete(extension),
        skipped_reason=_skipped_reason(extension),
        decision=extension.decision,
        decision_reason=extension.decision_reason,
        public_outcome=extension.public_outcome,
        decision_basis=extension.decision_basis,
        evidence_confidence=extension.evidence_confidence,
        provenance=dict(extension.provenance),
        capability_assessment=dict(extension.capability_assessment),
        score_schema_version=extension.score_schema_version,
        artifact_sha256=str(extension.artifact_identity.get("sha256") or extension.artifact_hash),
        coverage_percent=int(extension.analysis_coverage.get("coverage_percent") or 0),
        analysis_status=extension.analysis_status,
        baseline_changed=bool(extension.baseline_diff.get("baseline_changed")),
    )


def _to_detail(
    extension: ExtensionReport,
    *,
    include_raw_evidence: bool,
    policy_version: str,
) -> ExtensionDetail:
    evidence_store: dict[str, Any] = {}
    findings: list[dict[str, Any]] = []
    for finding in _rank_findings(extension.findings):
        finding_data = finding.to_dict()
        evidence_id = _evidence_id(finding_data)
        evidence_store[evidence_id] = _evidence_record(finding_data, include_raw_evidence=include_raw_evidence)
        finding_data["evidence_refs"] = [evidence_id]
        finding_data["evidence_class"] = _finding_evidence_class(finding)
        if policy_version == "legacy":
            finding_data["actionability"] = _legacy_finding_actionability(finding)
            finding_data["effective_severity"] = str(getattr(finding, "severity", "INFO"))
        else:
            finding_data["actionability"] = _finding_actionability(finding)
            finding_data["effective_severity"] = effective_finding_severity(finding)
        if not include_raw_evidence:
            finding_data.pop("evidence", None)
        finding_data["file_refs"] = list(finding_data.get("file_refs") or [])[:5]
        findings.append(finding_data)

    return ExtensionDetail(
        extension_id=extension.extension_id,
        name=extension.name,
        publisher=extension.publisher,
        version=extension.version,
        description=extension.description,
        repository=extension.repository,
        source=extension.source,
        verdict=extension.verdict,
        severity=extension.severity,
        risk_score=extension.risk_score,
        malware_score=extension.malware_score,
        context_score=_context_score(extension),
        grade=grade_extension(extension.verdict, extension.risk_score, extension.malware_score, extension.findings),
        verdict_state=_verdict_state(extension),
        verdict_label=_verdict_label(extension),
        score_details=extension.score_details,
        score_explanation=_score_explanation(extension),
        verdict_reason=extension.verdict_reason,
        recommendations=_recommendations(extension),
        findings=findings,
        evidence=evidence_store,
        manifest=_manifest(extension),
        dependencies=dict(list(extension.dependencies.items())[:200]),
        dependency_inventory=list(extension.artifact_inventory.get("dependency_inventory") or [])[:1000],
        artifact_inventory=dict(extension.artifact_inventory),
        security_dimensions=_security_dimensions(extension),
        capabilities={str(item.get("id") or index): item for index, item in enumerate(extension.capabilities) if isinstance(item, dict)},
        from_cache=bool(getattr(extension, "from_cache", False)),
        scan_incomplete=_scan_incomplete(extension),
        skipped_reason=_skipped_reason(extension),
        decision=extension.decision,
        decision_reason=extension.decision_reason,
        public_outcome=extension.public_outcome,
        decision_basis=extension.decision_basis,
        evidence_confidence=extension.evidence_confidence,
        provenance=dict(extension.provenance),
        capability_assessment=dict(extension.capability_assessment),
        score_schema_version=extension.score_schema_version,
        artifact_identity=dict(extension.artifact_identity),
        analysis_coverage=dict(extension.analysis_coverage),
        analysis_status=extension.analysis_status,
        baseline_diff=dict(extension.baseline_diff),
    )


def grade_extension(verdict: str, risk_score: int, malware_score: int, findings: list[Any] | None = None) -> str:
    has_high_or_medium = any(str(getattr(finding, "severity", "")) in {"HIGH", "MEDIUM", "CRITICAL"} for finding in findings or [])
    if verdict == "malicious" or malware_score >= 90:
        return "F"
    if verdict == "suspicious" or risk_score >= 75 or malware_score >= 70:
        return "D"
    if verdict == "review" and has_high_or_medium:
        return "C"
    if verdict == "review":
        return "B"
    if risk_score > 0 or malware_score > 0:
        return "A-"
    return "A"


_DIMENSION_CATEGORIES = {
    "behavior_safety": {"process", "network", "filesystem", "code", "cross-extension-exposure", "agent", "webview"},
    "supply_chain_integrity": {"supply-chain", "registry", "lifecycle", "provenance"},
    "dependency_health": {"dependency", "vulnerability"},
    "artifact_integrity": {"artifact", "obfuscation", "binary", "evasion"},
    "publisher_project_health": {"reputation", "repository-posture", "license"},
}


def _security_dimensions(extension: ExtensionReport) -> dict[str, Any]:
    severity_weight = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 9, "LOW": 3, "INFO": 0}
    dimensions: dict[str, Any] = {}
    for dimension, categories in _DIMENSION_CATEGORIES.items():
        deductions: list[dict[str, Any]] = []
        score = 100
        for finding in extension.findings:
            if finding.category not in categories:
                continue
            weight = severity_weight.get(finding.severity, 0)
            evidence_class = str((finding.evidence or {}).get("evidence_class") or "weak")
            if evidence_class in {"weak", "reputation"}:
                weight = max(1 if weight else 0, weight // 2)
            if weight:
                score -= weight
                deductions.append({"rule_id": finding.rule_id, "points": weight, "severity": finding.severity})
        final_score = max(0, score)
        dimensions[dimension] = {
            "score": final_score,
            "status": _dimension_status(final_score),
            "deductions": deductions[:20],
            "basis": "Deterministic evidence deductions; higher is better and is not a probability.",
        }

    coverage = extension.analysis_coverage or {}
    coverage_score = int(coverage.get("coverage_percent") or 0)
    providers = coverage.get("providers") if isinstance(coverage.get("providers"), dict) else {}
    unavailable = [
        name for name, provider in providers.items()
        if isinstance(provider, dict) and str(provider.get("status") or "") not in {"complete", "completed", "available"}
    ]
    dimensions["analysis_confidence"] = {
        "score": coverage_score,
        "status": "unknown" if coverage.get("status") != "complete" else _dimension_status(coverage_score),
        "deductions": [{"provider": name, "reason": "not complete"} for name in unavailable],
        "basis": "Executable coverage and recorded analyzer completion; higher is better.",
    }
    return dimensions


def _dimension_status(score: int) -> str:
    if score >= 90:
        return "strong"
    if score >= 70:
        return "attention"
    return "weak"


def _verdict_label(extension: ExtensionReport) -> str:
    return {
        "safe": "Safe",
        "safe_with_notes": "Safe with notes",
        "needs_review": "Needs review",
        "suspicious": "Suspicious",
        "confirmed_malicious": "Confirmed malicious",
    }[_verdict_state(extension)]


def _verdict_state(extension: ExtensionReport) -> str:
    if extension.verdict == "malicious":
        return "confirmed_malicious"
    if extension.verdict == "suspicious":
        return "suspicious"
    if extension.verdict == "review":
        return "needs_review"
    if _context_score(extension) > 0:
        return "safe_with_notes"
    return "safe"


def _context_score(extension: ExtensionReport) -> int:
    contextual = [finding for finding in extension.findings if _finding_actionability(finding) in {"contextual", "low"}]
    if not contextual:
        return 0
    components = extension.score_details.get("components") if isinstance(extension.score_details, dict) else {}
    reputation = int((components or {}).get("reputation") or 0)
    posture = int((components or {}).get("posture") or 0)
    weak = int((components or {}).get("weak_context") or 0)
    return min(100, max(reputation, posture, weak) + min(40, len(contextual) * 6))


def _finding_actionability(finding: Any) -> str:
    return finding_actionability(finding)


def _legacy_finding_actionability(finding: Any) -> str:
    evidence_class = _finding_evidence_class(finding)
    rule_id = str(getattr(finding, "rule_id", ""))
    severity = str(getattr(finding, "severity", ""))
    if evidence_class == "confirmed":
        return "block"
    if evidence_class in {"correlated", "observed"} and severity in {"HIGH", "CRITICAL"}:
        return "investigate"
    if evidence_class in {"dependency", "provenance", "capability", "posture", "exposure"}:
        if rule_id in {"startup-activation", "repo-url-missing", "security-policy-missing", "license-missing", "repo-maintained"}:
            return "contextual"
        return "review"
    return "contextual"


def _finding_evidence_class(finding: Any) -> str:
    return finding_evidence_class(finding)


def _score_explanation(extension: ExtensionReport) -> list[str]:
    explanations = [extension.verdict_reason]
    for finding in _rank_findings(extension.findings)[:6]:
        explanations.append(finding.evidence_summary)
    return list(dict.fromkeys(item for item in explanations if item))[:8]


def _recommendations(extension: ExtensionReport) -> list[Recommendation]:
    if extension.verdict == "malicious":
        return [Recommendation(
            priority="critical",
            title="Remove or block this extension",
            description=extension.verdict_reason,
            action="Uninstall the extension and investigate affected workspaces.",
        )]
    if extension.verdict == "suspicious":
        return [Recommendation(
            priority="high",
            title="Review extension before continued use",
            description=extension.verdict_reason,
            action="Review source or uninstall if behavior is unexpected.",
        )]
    if extension.verdict == "review":
        return [Recommendation(
            priority="medium",
            title="Review extension risk context",
            description=extension.verdict_reason,
            action="Confirm publisher intent, dependency posture, and requested IDE capabilities.",
        )]
    if extension.findings:
        return [Recommendation(
            priority="low",
            title="Keep monitoring contextual findings",
            description="The scanner found contextual signals that did not change the verdict.",
            action="Re-scan after extension updates or ruleset changes.",
        )]
    return []


def _activation_summary(extension: ExtensionReport) -> str:
    activation = []
    for capability in extension.capabilities:
        if isinstance(capability, dict) and capability.get("id") == "activation":
            activation = [str(item) for item in capability.get("evidence") or []]
            break
    if "*" in activation:
        return "broad activation"
    if "onStartupFinished" in activation:
        return "startup activation"
    if activation:
        return f"{len(activation)} activation event(s)"
    return "no activation events reported"


def _manifest(extension: ExtensionReport) -> dict[str, Any]:
    path = Path(extension.install_path)
    if path.suffix.lower() == ".vsix" or not path.exists() or not path.is_dir():
        return {}
    try:
        parsed = loads_jsonc((path / "package.json").read_text(encoding="utf-8"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _evidence_id(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    normalized = json.dumps({
        "rule_id": finding.get("rule_id"),
        "file_refs": finding.get("file_refs") or [],
        "summary": finding.get("evidence_summary") or "",
        "evidence": evidence,
    }, sort_keys=True, default=str)
    return "ev_" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _evidence_record(finding: dict[str, Any], *, include_raw_evidence: bool) -> dict[str, Any]:
    file_refs = list(finding.get("file_refs") or [])
    record = {
        "file": file_refs[0] if file_refs else "",
        "line": None,
        "summary": finding.get("evidence_summary") or "",
        "evidence_class": (finding.get("evidence") or {}).get("evidence_class") if isinstance(finding.get("evidence"), dict) else "weak",
    }
    if include_raw_evidence and isinstance(finding.get("evidence"), dict):
        record["raw"] = finding["evidence"]
    return record


def _rank_findings(findings: list[Any]) -> list[Any]:
    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return sorted(findings, key=lambda item: (
        severity_rank.get(str(getattr(item, "severity", "")), 0),
        int(getattr(item, "score", 0) or 0),
        str(getattr(item, "rule_id", "")),
    ), reverse=True)


def _rank_summaries(summaries: list[ExtensionSummary]) -> list[ExtensionSummary]:
    verdict_rank = {"malicious": 4, "suspicious": 3, "review": 2, "clean": 1}
    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return sorted(summaries, key=lambda item: (
        verdict_rank.get(item.verdict, 0),
        severity_rank.get(item.severity, 0),
        item.malware_score,
        item.risk_score,
        item.extension_id,
    ), reverse=True)


def _extension_from_dict(data: dict[str, Any]) -> ExtensionReport:
    from .models import Finding

    findings = [
        Finding(
            finding_id=str(item.get("finding_id") or ""),
            extension_id=str(item.get("extension_id") or data.get("extension_id") or ""),
            version=str(item.get("version") or data.get("version") or ""),
            rule_id=str(item.get("rule_id") or "unknown"),
            category=str(item.get("category") or "unknown"),
            severity=str(item.get("severity") or "INFO"),  # type: ignore[arg-type]
            confidence=float(item.get("confidence") or 0),
            score=int(item.get("score") or 0),
            evidence_type=str(item.get("evidence_type") or "static"),
            evidence_summary=str(item.get("evidence_summary") or ""),
            file_refs=[str(ref) for ref in item.get("file_refs") or []],
            recommendation=str(item.get("recommendation") or ""),
            evidence=item.get("evidence") if isinstance(item.get("evidence"), dict) else None,
        )
        for item in data.get("findings") or []
        if isinstance(item, dict)
    ]
    return ExtensionReport(
        instance_id=str(data.get("instance_id") or ""),
        extension_id=str(data.get("extension_id") or ""),
        name=str(data.get("name") or ""),
        publisher=str(data.get("publisher") or ""),
        version=str(data.get("version") or ""),
        description=str(data.get("description") or ""),
        repository=str(data.get("repository") or ""),
        install_path=str(data.get("install_path") or ""),
        source=str(data.get("source") or ""),
        artifact_hash=str(data.get("artifact_hash") or ""),
        severity=str(data.get("severity") or "INFO"),  # type: ignore[arg-type]
        verdict=str(data.get("verdict") or "clean"),  # type: ignore[arg-type]
        malware_authority=str(data.get("malware_authority") or "none"),
        verdict_reason=str(data.get("verdict_reason") or ""),
        malware_score=int(data.get("malware_score") or 0),
        risk_score=int(data.get("risk_score") or 0),
        score_details=data.get("score_details") if isinstance(data.get("score_details"), dict) else {},
        capabilities=data.get("capabilities") if isinstance(data.get("capabilities"), list) else [],
        artifact_inventory=data.get("artifact_inventory") if isinstance(data.get("artifact_inventory"), dict) else {},
        findings=findings,
        scanned_files=int(data.get("scanned_files") or 0),
        dependencies=data.get("dependencies") if isinstance(data.get("dependencies"), dict) else {},
        decision=str(data.get("decision") or "incomplete"),  # type: ignore[arg-type]
        decision_reason=str(data.get("decision_reason") or "Analysis has not completed."),
        public_outcome=str(data.get("public_outcome") or "incomplete"),  # type: ignore[arg-type]
        decision_basis=str(data.get("decision_basis") or "incomplete"),
        evidence_confidence=str(data.get("evidence_confidence") or "none"),
        provenance=data.get("provenance") if isinstance(data.get("provenance"), dict) else {},
        capability_assessment=data.get("capability_assessment") if isinstance(data.get("capability_assessment"), dict) else {},
        score_schema_version=str(data.get("score_schema_version") or "1"),
        artifact_identity=data.get("artifact_identity") if isinstance(data.get("artifact_identity"), dict) else {},
        analysis_coverage=data.get("analysis_coverage") if isinstance(data.get("analysis_coverage"), dict) else {},
        analysis_status=_analysis_status_from_dict(data),  # type: ignore[arg-type]
        baseline_diff=data.get("baseline_diff") if isinstance(data.get("baseline_diff"), dict) else {},
    )


def _analysis_status_from_dict(data: dict[str, Any]) -> str:
    explicit = str(data.get("analysis_status") or "")
    if explicit in {"complete", "incomplete", "failed"}:
        return explicit
    coverage = data.get("analysis_coverage") if isinstance(data.get("analysis_coverage"), dict) else {}
    providers = coverage.get("providers") if isinstance(coverage.get("providers"), dict) else {}
    acquisition = providers.get("artifact_acquisition") if isinstance(providers, dict) else None
    manifest = coverage.get("manifest_validation") if isinstance(coverage.get("manifest_validation"), dict) else {}
    if (
        data.get("source") == "marketplace-error"
        or (isinstance(acquisition, dict) and acquisition.get("status") == "failed")
        or manifest.get("status") == "scan-aborted"
    ):
        return "failed"
    inventory = data.get("artifact_inventory") if isinstance(data.get("artifact_inventory"), dict) else {}
    if inventory.get("scan_incomplete") or coverage.get("status") == "incomplete" or data.get("decision") == "incomplete":
        return "incomplete"
    if coverage.get("status") == "complete" or data.get("decision") in {"allow", "review", "block"}:
        return "complete"
    return "incomplete"


def _scan_incomplete(extension: ExtensionReport) -> bool:
    return bool(
        extension.analysis_status != "complete"
        or getattr(extension, "scan_incomplete", False)
        or extension.artifact_inventory.get("scan_incomplete")
    )


def _skipped_reason(extension: ExtensionReport) -> str:
    return str(getattr(extension, "skipped_reason", "") or extension.artifact_inventory.get("skipped_reason") or "")


def _safe_detail_name(extension_id: str, version_value: str) -> str:
    raw = f"{extension_id}@{version_value}"
    return re.sub(r"[^A-Za-z0-9._@-]+", "_", raw).strip("._") or "extension"


def _sorted_counts(counts: dict[str, int]) -> dict[str, int]:
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _scanner_version() -> str:
    for distribution_name in ("guardlens-core", "guardlens"):
        try:
            return version(distribution_name)
        except PackageNotFoundError:
            continue
    return "unknown"


def _scanner_build() -> str:
    """Return the immutable CI revision when one is available.

    Local reports deliberately say ``unknown`` rather than pretending to be a
    production build. The website treats an unknown build as non-reusable.
    """
    return os.environ.get("IDE_SCANNER_BUILD_SHA", "").strip() or "unknown"


def _write_json(archive: zipfile.ZipFile, name: str, data: Any) -> None:
    archive.writestr(name, json.dumps(data, indent=2, sort_keys=True) + "\n")
