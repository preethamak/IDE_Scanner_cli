from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .runner import load_report

PRODUCTION_CORPUS_SCHEMA_VERSION = "1.0"
HOLDOUT_CORPUS_SCHEMA_VERSION = "1.0"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LABELS = {"known_safe", "gray", "known_malicious"}
VERDICTS = {"clean", "review", "suspicious", "malicious"}
DECISIONS = {"allow", "review", "block"}
ANALYSIS_STATUSES = {"complete", "incomplete", "failed"}
# A known-safe artifact routed to REVIEW is a false-positive/noise signal even
# when it is not blocked. Keep the publication SLO explicit: at most one in
# five independently labelled safe artifacts may require review.
MAX_SAFE_REVIEW_RATE = 0.2


def load_production_corpus(path: Path | str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_production_corpus(data)
    return data


def validate_production_corpus(data: Any) -> None:
    if not isinstance(data, dict) or data.get("schema_version") != PRODUCTION_CORPUS_SCHEMA_VERSION:
        raise ValueError(f"Production corpus schema_version must be {PRODUCTION_CORPUS_SCHEMA_VERSION}")
    corpus_id = data.get("corpus_id")
    if not isinstance(corpus_id, str) or not corpus_id.strip():
        raise ValueError("Production corpus requires a corpus_id")
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("Production corpus requires a non-empty artifacts array")
    seen: set[tuple[str, str, str]] = set()
    for index, artifact in enumerate(artifacts):
        _validate_artifact(artifact, index, seen)
    thresholds = data.get("thresholds")
    if not isinstance(thresholds, dict):
        raise ValueError("Production corpus requires thresholds")
    for key in ("required_pass_rate", "max_safe_block_rate", "max_safe_review_rate", "max_malicious_allow_rate"):
        value = thresholds.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
            raise ValueError(f"Production corpus threshold {key} must be between 0 and 1")
    maximum_incomplete = thresholds.get("max_incomplete_required")
    if isinstance(maximum_incomplete, bool) or not isinstance(maximum_incomplete, int) or maximum_incomplete < 0:
        raise ValueError("Production corpus threshold max_incomplete_required must be a non-negative integer")


def evaluate_production_corpus(
    corpus_path: Path | str,
    report_path: Path | str,
    *,
    require_identity: bool = False,
    expected_scanner_build: str | None = None,
) -> dict[str, Any]:
    corpus = load_production_corpus(corpus_path)
    report = load_report(Path(report_path))
    report_identity = _report_identity(report)
    actual_by_identity = {
        _actual_key(item): item
        for item in report.get("extensions") or []
        if isinstance(item, dict)
    }
    rows = [
        _evaluate_artifact(expected, actual_by_identity.get(_expected_key(expected)))
        for expected in corpus["artifacts"]
    ]
    summary = _summary(rows)
    thresholds = dict(corpus["thresholds"])
    gate_checks = {
        "required_pass_rate": summary["required_pass_rate"] >= thresholds["required_pass_rate"],
        "safe_block_rate": summary["safe_block_rate"] <= thresholds["max_safe_block_rate"],
        "safe_review_rate": summary["safe_review_rate"] <= thresholds["max_safe_review_rate"],
        "malicious_allow_rate": summary["malicious_allow_rate"] <= thresholds["max_malicious_allow_rate"],
        "incomplete_required": summary["incomplete_required"] <= thresholds["max_incomplete_required"],
    }
    if require_identity:
        identity_is_complete = all(
            report_identity[key] not in {"", "unknown", "legacy"}
            for key in ("scanner_build", "policy_version", "ruleset_version")
        )
        if expected_scanner_build is not None:
            identity_is_complete = identity_is_complete and report_identity["scanner_build"] == expected_scanner_build
        gate_checks["report_identity"] = identity_is_complete
    gate_passed = all(gate_checks.values())
    return {
        "schema_version": PRODUCTION_CORPUS_SCHEMA_VERSION,
        "corpus_id": corpus["corpus_id"],
        "corpus_version": corpus.get("corpus_version", "unknown"),
        "report_identity": report_identity,
        "gate": {
            "passed": gate_passed,
            "checks": gate_checks,
            "thresholds": thresholds,
        },
        "summary": summary,
        "verdict_confusion": _verdict_confusion(rows),
        "rule_matrix": _rule_matrix(corpus["artifacts"], rows),
        "artifacts": rows,
    }


def evaluate_holdout_corpus(
    corpus_path: Path | str,
    report_path: Path | str,
    *,
    require_runtime: bool = True,
    require_malicious_block: bool = True,
    require_identity: bool = False,
    expected_scanner_build: str | None = None,
) -> dict[str, Any]:
    """Evaluate a frozen, independently labelled exact-artifact holdout.

    The production regression corpus carries rule-level expectations for
    synthetic and curated fixtures. A holdout deliberately does not: its
    labels are fixed before scanning, and the scanner must be judged against
    the complete exact bytes without teaching the scanner the expected rule.
    Runtime is required by default so a passing holdout cannot be mistaken for
    evidence that the dynamic path was exercised.
    """
    corpus = _load_holdout_corpus(Path(corpus_path))
    report = load_report(Path(report_path))
    actual_by_identity = {
        _actual_key(item): item
        for item in report.get("extensions") or []
        if isinstance(item, dict)
    }
    rows = [
        _evaluate_holdout_artifact(
            expected,
            actual_by_identity.get(_expected_key(expected)),
            require_runtime=require_runtime,
            require_malicious_block=require_malicious_block,
        )
        for expected in corpus["artifacts"]
    ]
    execution = _corpus_execution(report)
    runtime_enabled = execution.get("runtime_enabled") is True
    deep_profile = str(execution.get("profile") or "") == "deep"
    external_syscall_trace = execution.get("external_syscall_trace") is True
    summary = _holdout_summary(rows)
    checks = {
        "required_pass_rate": summary["required_pass_rate"] == 1.0,
        "safe_block_rate": summary["safe_block_rate"] == 0.0,
        "safe_review_rate": summary["safe_review_rate"] <= MAX_SAFE_REVIEW_RATE,
        "malicious_allow_rate": summary["malicious_allow_rate"] == 0.0,
        "incomplete_required": summary["incomplete_required"] == 0,
        "runtime_enabled": runtime_enabled if require_runtime else True,
        "deep_profile": deep_profile if require_runtime else True,
        "external_syscall_trace": external_syscall_trace if require_runtime else True,
    }
    report_identity = _report_identity(report)
    if require_identity:
        identity_is_complete = all(
            report_identity[key] not in {"", "unknown", "legacy"}
            for key in ("scanner_build", "policy_version", "ruleset_version")
        )
        if expected_scanner_build is not None:
            identity_is_complete = identity_is_complete and report_identity["scanner_build"] == expected_scanner_build
        checks["report_identity"] = identity_is_complete
    return {
        "schema_version": HOLDOUT_CORPUS_SCHEMA_VERSION,
        "corpus_id": corpus["corpus_id"],
        "corpus_version": corpus["corpus_version"],
        "report_identity": report_identity,
        "runtime_evidence": {
            "required": require_runtime,
            "runtime_enabled": runtime_enabled,
            "profile": execution.get("profile") or "unknown",
            "external_syscall_trace": external_syscall_trace,
            "runtime_timeout_seconds": execution.get("runtime_timeout_seconds", 0),
        },
        "classification_mode": "intel-backed" if require_malicious_block else "behavior-only",
        "advisory_snapshot": execution.get("extension_advisories") if isinstance(execution.get("extension_advisories"), dict) else {},
        "gate": {
            "passed": all(checks.values()),
            "checks": checks,
            "thresholds": {
                "required_pass_rate": 1.0,
                "max_safe_block_rate": 0.0,
                "max_safe_review_rate": MAX_SAFE_REVIEW_RATE,
                "max_malicious_allow_rate": 0.0,
                "max_incomplete_required": 0,
            },
        },
        "summary": summary,
        "verdict_confusion": _verdict_confusion(rows),
        "rule_matrix": _holdout_rule_matrix(rows),
        "artifacts": rows,
    }


def _load_holdout_corpus(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Holdout corpus could not be read: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != HOLDOUT_CORPUS_SCHEMA_VERSION:
        raise ValueError(f"Holdout corpus schema_version must be {HOLDOUT_CORPUS_SCHEMA_VERSION}")
    if not str(value.get("corpus_id") or "").strip() or not str(value.get("corpus_version") or "").strip():
        raise ValueError("Holdout corpus requires corpus_id and corpus_version")
    metadata = value.get("holdout")
    if not isinstance(metadata, dict) or metadata.get("status") != "fresh-labeled":
        raise ValueError("Holdout corpus must declare status fresh-labeled")
    if metadata.get("frozen_before_scan") is not True or metadata.get("original_bytes_available") is not True:
        raise ValueError("Holdout corpus must be frozen before scanning with original bytes available")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("Holdout corpus requires a non-empty artifacts array")
    seen: set[tuple[str, str, str]] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise ValueError(f"Holdout artifact {index} must be an object")
        extension_id = str(artifact.get("extension_id") or "").strip()
        version = str(artifact.get("version") or "").strip()
        target_platform = str(artifact.get("target_platform") or "").strip().lower()
        key = (_normalized_id(extension_id), version, target_platform)
        if not extension_id or "." not in extension_id or not version or key in seen:
            raise ValueError(f"Holdout artifact {index} has an invalid or duplicate identity")
        seen.add(key)
        if artifact.get("gate_required") is not True or artifact.get("label") not in {"known_safe", "known_malicious"}:
            raise ValueError(f"Holdout artifact {index} must be a required known_safe or known_malicious label")
        source = artifact.get("artifact")
        if not isinstance(source, dict) or source.get("original_bytes_available") is not True:
            raise ValueError(f"Holdout artifact {index} must retain original bytes")
        source_type = str(source.get("source_type") or "")
        if not source_type or source_type == "fixture_directory":
            raise ValueError(f"Holdout artifact {index} cannot use a synthetic fixture source")
        if not SHA256_RE.fullmatch(str(source.get("sha256") or "").lower()):
            raise ValueError(f"Holdout artifact {index} requires a SHA-256")
    return value


def _corpus_execution(report: dict[str, Any]) -> dict[str, Any]:
    direct = report.get("corpus_execution")
    if isinstance(direct, dict):
        return direct
    intelligence = report.get("intelligence")
    if isinstance(intelligence, dict) and isinstance(intelligence.get("corpus_execution"), dict):
        return intelligence["corpus_execution"]
    metadata = report.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("intelligence_snapshot"), dict):
        snapshot = metadata["intelligence_snapshot"]
        if isinstance(snapshot.get("corpus_execution"), dict):
            return snapshot["corpus_execution"]
    return {}


def _report_identity(report: dict[str, Any]) -> dict[str, str]:
    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    return {
        "scanner_build": str(report.get("scanner_build") or metadata.get("scanner_build") or "unknown"),
        "policy_version": str(report.get("policy_version") or metadata.get("policy_version") or "legacy"),
        "ruleset_version": str(report.get("ruleset_version") or metadata.get("ruleset_version") or "legacy"),
    }


def _evaluate_holdout_artifact(
    expected: dict[str, Any],
    actual: dict[str, Any] | None,
    *,
    require_runtime: bool,
    require_malicious_block: bool,
) -> dict[str, Any]:
    violations: list[str] = []
    if actual is None:
        violations.append("artifact was not present in the scanner report")
        return _holdout_row(expected, None, violations)
    analysis_status = str(actual.get("analysis_status") or "incomplete")
    decision = str(actual.get("decision") or "missing")
    verdict = str(actual.get("verdict") or "missing")
    if analysis_status != "complete":
        violations.append(f"analysis_status {analysis_status!r} is not complete")
    if decision not in {"allow", "review", "block"}:
        violations.append(f"decision {decision!r} is not a publishable complete decision")
    runtime_contract = _runtime_contract(actual)
    if require_runtime:
        violations.extend(_runtime_contract_violations(runtime_contract))
    label = expected["label"]
    if label == "known_safe":
        if decision == "block" or verdict == "malicious":
            violations.append("known-safe artifact was blocked or classified malicious")
    else:
        if require_malicious_block and decision != "block":
            violations.append(f"known-malicious artifact was not blocked (decision={decision!r})")
        if not require_malicious_block and decision not in {"review", "block"}:
            violations.append(f"known-malicious artifact was not detected (decision={decision!r})")
        allowed_verdicts = {"suspicious", "malicious"}
        if not require_malicious_block:
            # Behavior-only replay deliberately has no trusted advisory. A
            # high-risk quarantine decision is still a detection even when the
            # public verdict remains REVIEW rather than claiming MALICIOUS.
            allowed_verdicts.add("review")
        if verdict not in allowed_verdicts:
            violations.append(
                f"known-malicious artifact verdict {verdict!r} is not one of {sorted(allowed_verdicts)}"
            )
    expected_hash = str((expected.get("artifact") or {}).get("sha256") or "").lower()
    actual_hash = str(actual.get("artifact_hash") or (actual.get("artifact_identity") or {}).get("sha256") or "").lower()
    if actual_hash != expected_hash:
        violations.append("artifact SHA-256 does not match the frozen holdout")
    return _holdout_row(expected, actual, violations, runtime_contract=runtime_contract)


def _holdout_row(
    expected: dict[str, Any],
    actual: dict[str, Any] | None,
    violations: list[str],
    *,
    runtime_contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "extension_id": expected["extension_id"],
        "version": expected["version"],
        "target_platform": str(expected.get("target_platform") or ""),
        "label": expected["label"],
        "gate_required": True,
        "scanned": actual is not None,
        "passed": not violations,
        "gate_passed": not violations,
        "violations": violations,
        "actual": {} if actual is None else {
            "verdict": actual.get("verdict"),
            "decision": actual.get("decision"),
            "analysis_status": actual.get("analysis_status"),
            "risk_score": actual.get("risk_score"),
            "malware_score": actual.get("malware_score"),
            "artifact_sha256": actual.get("artifact_hash") or (actual.get("artifact_identity") or {}).get("sha256"),
            "runtime_contract": runtime_contract or {},
            "rule_ids": sorted({
                str(item.get("rule_id"))
                for item in actual.get("findings") or []
                if isinstance(item, dict) and item.get("rule_id")
            }),
        },
    }


def _runtime_contract(actual: dict[str, Any]) -> dict[str, Any]:
    coverage = actual.get("analysis_coverage") if isinstance(actual.get("analysis_coverage"), dict) else {}
    providers = coverage.get("providers") if isinstance(coverage.get("providers"), dict) else {}
    provider = providers.get("dynamic_sandbox") if isinstance(providers.get("dynamic_sandbox"), dict) else {}
    return {
        "coverage_status": str(coverage.get("status") or ""),
        "required_providers_complete": coverage.get("required_providers_complete") is True,
        # Preserve an absent/malformed declaration as unknown. Treating it as
        # ``False`` would let a missing provider masquerade as explicitly
        # not-applicable coverage.
        "required": provider.get("required") if isinstance(provider.get("required"), bool) else None,
        "provider_status": str(provider.get("status") or ""),
        "runtime_run_status": str(provider.get("runtime_run_status") or ""),
        "execution": str(provider.get("execution") or ""),
        "runtime_policy": str(provider.get("policy") or ""),
        "executed": provider.get("executed") is True,
        "external_syscall_trace": provider.get("external_syscall_trace") is True,
    }


def _runtime_contract_violations(contract: dict[str, Any]) -> list[str]:
    if contract.get("coverage_status") != "complete" or contract.get("required_providers_complete") is not True:
        return ["required analysis coverage is not complete"]
    if contract.get("required") is True:
        expected = {
            "provider_status": "completed",
            "runtime_run_status": "completed",
            "execution": "controlled-bubblewrap",
            "runtime_policy": "capability-gated-v1",
            "executed": True,
            "external_syscall_trace": True,
        }
    elif contract.get("required") is False:
        expected = {
            "provider_status": "not-applicable",
            "execution": "policy-gated",
            "runtime_policy": "capability-gated-v1",
            "executed": False,
            "external_syscall_trace": False,
        }
    else:
        return ["runtime contract required flag is missing or invalid"]
    mismatches = [
        f"runtime contract {field}={contract.get(field)!r} expected {value!r}"
        for field, value in expected.items()
        if contract.get(field) != value
    ]
    return mismatches


def _holdout_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    safe = [row for row in rows if row["scanned"] and row["label"] == "known_safe"]
    malicious = [row for row in rows if row["scanned"] and row["label"] == "known_malicious"]
    safe_blocks = sum(1 for row in safe if row["actual"].get("decision") == "block" or row["actual"].get("verdict") == "malicious")
    safe_reviewed = sum(1 for row in safe if _is_review_or_higher(row["actual"]))
    malicious_allows = sum(1 for row in malicious if row["actual"].get("decision") == "allow" or row["actual"].get("verdict") == "clean")
    malicious_blocked = sum(1 for row in malicious if row["actual"].get("decision") == "block")
    malicious_reviewed = sum(1 for row in malicious if row["actual"].get("decision") == "review")
    malicious_detected = sum(1 for row in malicious if _is_review_or_higher(row["actual"]))
    dynamic_required = sum(
        1 for row in rows
        if row["scanned"] and row["actual"].get("runtime_contract", {}).get("required") is True
    )
    dynamic_not_applicable = sum(
        1 for row in rows
        if row["scanned"] and row["actual"].get("runtime_contract", {}).get("required") is False
    )
    required_passed = sum(1 for row in rows if row["passed"])
    return {
        "total_artifacts": len(rows),
        "scanned_artifacts": sum(1 for row in rows if row["scanned"]),
        "not_scanned": sum(1 for row in rows if not row["scanned"]),
        "required_artifacts": len(rows),
        "required_passed": required_passed,
        "required_failed": len(rows) - required_passed,
        "required_pass_rate": round(required_passed / len(rows), 4) if rows else 0.0,
        "safe_evaluated": len(safe),
        "safe_blocks": safe_blocks,
        "safe_block_rate": round(safe_blocks / len(safe), 4) if safe else 0.0,
        "safe_reviewed": safe_reviewed,
        "safe_review_rate": round(safe_reviewed / len(safe), 4) if safe else 0.0,
        "malicious_evaluated": len(malicious),
        "malicious_allows": malicious_allows,
        "malicious_allow_rate": round(malicious_allows / len(malicious), 4) if malicious else 0.0,
        "malicious_blocked": malicious_blocked,
        "malicious_block_rate": round(malicious_blocked / len(malicious), 4) if malicious else 0.0,
        "malicious_reviewed": malicious_reviewed,
        "malicious_review_rate": round(malicious_reviewed / len(malicious), 4) if malicious else 0.0,
        "malicious_detected": malicious_detected,
        "malicious_detection_rate": round(malicious_detected / len(malicious), 4) if malicious else 0.0,
        "dynamic_required": dynamic_required,
        "dynamic_not_applicable": dynamic_not_applicable,
        "incomplete_required": sum(
            1 for row in rows
            if not row["scanned"] or row["actual"].get("analysis_status") != "complete"
        ),
    }


def _holdout_rule_matrix(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    matrix: dict[str, dict[str, int]] = {}
    for row in rows:
        if not row["scanned"]:
            continue
        label_key = f"fired_on_{row['label']}"
        for rule_id in row["actual"].get("rule_ids") or []:
            cell = matrix.setdefault(rule_id, {"fired_on_known_safe": 0, "fired_on_known_malicious": 0})
            cell[label_key] = cell.get(label_key, 0) + 1
    return dict(sorted(matrix.items()))


def _is_review_or_higher(actual: dict[str, Any]) -> bool:
    return (
        str(actual.get("decision") or "") in {"review", "block"}
        or str(actual.get("verdict") or "") in {"review", "suspicious", "malicious"}
    )


def _verdict_confusion(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    matrix: dict[str, dict[str, int]] = {}
    for row in rows:
        label = str(row["label"])
        verdict = str(row["actual"].get("verdict") or "not_scanned") if row["scanned"] else "not_scanned"
        matrix.setdefault(label, {})
        matrix[label][verdict] = matrix[label].get(verdict, 0) + 1
    return {label: dict(sorted(cells.items())) for label, cells in sorted(matrix.items())}


def _rule_matrix(artifacts: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per-rule fire counts by corpus label plus required-rule recall.

    A rule firing on known_safe artifacts is the corpus-level false-positive
    signal used to demote noisy rules; required-rule misses on known_malicious
    artifacts are the recall signal."""
    required_by_identity = {
        (_normalized_id(item.get("extension_id")), str(item.get("version") or "unknown")):
            set((item.get("expected") or {}).get("required_rule_ids") or [])
        for item in artifacts
    }
    matrix: dict[str, dict[str, Any]] = {}

    def cell(rule_id: str) -> dict[str, Any]:
        return matrix.setdefault(rule_id, {
            "fired_on_known_safe": 0,
            "fired_on_gray": 0,
            "fired_on_known_malicious": 0,
            "required_hits": 0,
            "required_misses": 0,
        })

    for row in rows:
        if not row["scanned"]:
            continue
        label = str(row["label"])
        fired = set(row["actual"].get("rule_ids") or [])
        for rule_id in fired:
            cell(rule_id)[f"fired_on_{label}"] += 1
        required = required_by_identity.get((_normalized_id(row["extension_id"]), str(row["version"])), set())
        for rule_id in required:
            key = "required_hits" if rule_id in fired else "required_misses"
            cell(rule_id)[key] += 1
    return dict(sorted(matrix.items()))


def _validate_artifact(artifact: Any, index: int, seen: set[tuple[str, str, str]]) -> None:
    prefix = f"Production corpus artifact {index}"
    if not isinstance(artifact, dict):
        raise ValueError(f"{prefix} must be an object")
    extension_id = artifact.get("extension_id")
    version = artifact.get("version")
    if not isinstance(extension_id, str) or "." not in extension_id:
        raise ValueError(f"{prefix} requires a publisher.extension identity")
    if not isinstance(version, str) or not version.strip() or version == "latest":
        raise ValueError(f"{prefix} requires an exact version")
    target_platform = artifact.get("target_platform", "")
    if not isinstance(target_platform, str):
        raise ValueError(f"{prefix} target_platform must be a string")
    identity = (_normalized_id(extension_id), version, target_platform.strip().lower())
    if identity in seen:
        raise ValueError(f"Production corpus contains duplicate artifact {extension_id}@{version}")
    seen.add(identity)
    if artifact.get("label") not in LABELS:
        raise ValueError(f"{prefix} has an unsupported label")
    if not isinstance(artifact.get("category"), str) or not artifact["category"].strip():
        raise ValueError(f"{prefix} requires a category")
    if not isinstance(artifact.get("gate_required"), bool):
        raise ValueError(f"{prefix} requires boolean gate_required")
    source = artifact.get("artifact")
    if not isinstance(source, dict) or not isinstance(source.get("source_type"), str):
        raise ValueError(f"{prefix} requires artifact.source_type")
    digest = str(source.get("sha256") or "").lower()
    if digest and not SHA256_RE.fullmatch(digest):
        raise ValueError(f"{prefix} artifact SHA-256 is invalid")
    if source.get("original_bytes_available") is True and not digest and source.get("source_type") != "fixture_directory":
        raise ValueError(f"{prefix} requires SHA-256 when original bytes are available")
    expected = artifact.get("expected")
    if not isinstance(expected, dict):
        raise ValueError(f"{prefix} requires expected constraints")
    _validate_choice_list(expected, "allowed_verdicts", VERDICTS, prefix)
    _validate_choice_list(expected, "allowed_decisions", DECISIONS, prefix)
    _validate_choice_list(expected, "allowed_analysis_statuses", ANALYSIS_STATUSES, prefix)
    for key in ("required_rule_ids", "forbidden_rule_ids"):
        values = expected.get(key, [])
        if not isinstance(values, list) or not all(isinstance(item, str) and item for item in values):
            raise ValueError(f"{prefix} expected.{key} must be an array of rule ids")
    for key in ("min_risk_score", "max_risk_score", "min_malware_score", "max_malware_score"):
        value = expected.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100):
            raise ValueError(f"{prefix} expected.{key} must be an integer from 0 to 100")


def _validate_choice_list(expected: dict[str, Any], key: str, choices: set[str], prefix: str) -> None:
    values = expected.get(key)
    if not isinstance(values, list) or not values or not all(item in choices for item in values):
        raise ValueError(f"{prefix} expected.{key} contains unsupported values")


def _evaluate_artifact(expected: dict[str, Any], actual: dict[str, Any] | None) -> dict[str, Any]:
    constraints = expected["expected"]
    violations: list[str] = []
    if actual is None:
        violations.append("artifact was not present in the scanner report")
        return _row(expected, None, violations)
    verdict = str(actual.get("verdict") or "missing")
    decision = str(actual.get("decision") or "missing")
    analysis_status = str(actual.get("analysis_status") or "incomplete")
    if verdict not in constraints["allowed_verdicts"]:
        violations.append(f"verdict {verdict!r} is not allowed")
    if decision not in constraints["allowed_decisions"]:
        violations.append(f"decision {decision!r} is not allowed")
    if analysis_status not in constraints["allowed_analysis_statuses"]:
        violations.append(f"analysis_status {analysis_status!r} is not allowed")
    rule_ids = {str(item.get("rule_id")) for item in actual.get("findings") or [] if isinstance(item, dict)}
    for rule_id in constraints.get("required_rule_ids", []):
        if rule_id not in rule_ids:
            violations.append(f"required rule {rule_id!r} was not reported")
    for rule_id in constraints.get("forbidden_rule_ids", []):
        if rule_id in rule_ids:
            violations.append(f"forbidden rule {rule_id!r} was reported")
    for score_name in ("risk_score", "malware_score"):
        score = actual.get(score_name)
        minimum = constraints.get(f"min_{score_name}")
        maximum = constraints.get(f"max_{score_name}")
        if isinstance(minimum, int) and (not isinstance(score, int) or score < minimum):
            violations.append(f"{score_name} is below {minimum}")
        if isinstance(maximum, int) and (not isinstance(score, int) or score > maximum):
            violations.append(f"{score_name} exceeds {maximum}")
    expected_hash = str((expected.get("artifact") or {}).get("sha256") or "").lower()
    actual_hash = str(actual.get("artifact_hash") or (actual.get("artifact_identity") or {}).get("sha256") or "").lower()
    if expected_hash and actual_hash != expected_hash:
        violations.append("artifact SHA-256 does not match the corpus")
    return _row(expected, actual, violations)


def _row(expected: dict[str, Any], actual: dict[str, Any] | None, violations: list[str]) -> dict[str, Any]:
    required = bool(expected["gate_required"])
    scanned = actual is not None
    return {
        "extension_id": expected["extension_id"],
        "version": expected["version"],
        "target_platform": str(expected.get("target_platform") or ""),
        "category": expected["category"],
        "label": expected["label"],
        "gate_required": required,
        "scanned": scanned,
        "passed": not violations,
        "gate_passed": not violations or not required,
        "violations": violations,
        "actual": {} if actual is None else {
            "verdict": actual.get("verdict"),
            "decision": actual.get("decision"),
            "analysis_status": actual.get("analysis_status"),
            "risk_score": actual.get("risk_score"),
            "malware_score": actual.get("malware_score"),
            "artifact_sha256": actual.get("artifact_hash") or (actual.get("artifact_identity") or {}).get("sha256"),
            "rule_ids": sorted({
                str(item.get("rule_id")) for item in actual.get("findings") or [] if isinstance(item, dict)
            }),
        },
    }


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    required = [row for row in rows if row["gate_required"]]
    safe = [row for row in rows if row["scanned"] and row["label"] == "known_safe"]
    malicious = [row for row in rows if row["scanned"] and row["label"] == "known_malicious"]
    safe_blocks = sum(1 for row in safe if row["actual"].get("decision") == "block" or row["actual"].get("verdict") == "malicious")
    safe_reviewed = sum(1 for row in safe if _is_review_or_higher(row["actual"]))
    malicious_allows = sum(1 for row in malicious if row["actual"].get("decision") == "allow")
    malicious_blocked = sum(1 for row in malicious if row["actual"].get("decision") == "block")
    malicious_reviewed = sum(1 for row in malicious if row["actual"].get("decision") == "review")
    malicious_detected = sum(1 for row in malicious if _is_review_or_higher(row["actual"]))
    incomplete_required = sum(
        1 for row in required
        if not row["scanned"] or row["actual"].get("analysis_status") != "complete"
    )
    required_passed = sum(1 for row in required if row["passed"])
    return {
        "total_artifacts": len(rows),
        "scanned_artifacts": sum(1 for row in rows if row["scanned"]),
        "not_scanned": sum(1 for row in rows if not row["scanned"]),
        "required_artifacts": len(required),
        "required_passed": required_passed,
        "required_failed": len(required) - required_passed,
        "required_pass_rate": round(required_passed / len(required), 4) if required else 1.0,
        "safe_evaluated": len(safe),
        "safe_blocks": safe_blocks,
        "safe_block_rate": round(safe_blocks / len(safe), 4) if safe else 0.0,
        "safe_reviewed": safe_reviewed,
        "safe_review_rate": round(safe_reviewed / len(safe), 4) if safe else 0.0,
        "malicious_evaluated": len(malicious),
        "malicious_allows": malicious_allows,
        "malicious_allow_rate": round(malicious_allows / len(malicious), 4) if malicious else 0.0,
        "malicious_blocked": malicious_blocked,
        "malicious_block_rate": round(malicious_blocked / len(malicious), 4) if malicious else 0.0,
        "malicious_reviewed": malicious_reviewed,
        "malicious_review_rate": round(malicious_reviewed / len(malicious), 4) if malicious else 0.0,
        "malicious_detected": malicious_detected,
        "malicious_detection_rate": round(malicious_detected / len(malicious), 4) if malicious else 0.0,
        "incomplete_required": incomplete_required,
    }


def _normalized_id(value: Any) -> str:
    return str(value or "").strip().lower()


def _expected_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (
        _normalized_id(item.get("extension_id")),
        str(item.get("version") or "unknown"),
        str(item.get("target_platform") or "").strip().lower(),
    )


def _actual_key(item: dict[str, Any]) -> tuple[str, str, str]:
    identity = item.get("artifact_identity") if isinstance(item.get("artifact_identity"), dict) else {}
    return (
        _normalized_id(item.get("extension_id")),
        str(item.get("version") or "unknown"),
        str(identity.get("target_platform") or item.get("target_platform") or "").strip().lower(),
    )
