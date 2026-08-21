from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .runner import load_report

PRODUCTION_CORPUS_SCHEMA_VERSION = "1.0"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LABELS = {"known_safe", "gray", "known_malicious"}
VERDICTS = {"clean", "review", "suspicious", "malicious"}
DECISIONS = {"allow", "review", "block", "incomplete"}
ANALYSIS_STATUSES = {"complete", "incomplete", "failed"}


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
    for key in ("required_pass_rate", "max_safe_block_rate", "max_malicious_allow_rate"):
        value = thresholds.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
            raise ValueError(f"Production corpus threshold {key} must be between 0 and 1")
    maximum_incomplete = thresholds.get("max_incomplete_required")
    if isinstance(maximum_incomplete, bool) or not isinstance(maximum_incomplete, int) or maximum_incomplete < 0:
        raise ValueError("Production corpus threshold max_incomplete_required must be a non-negative integer")


def evaluate_production_corpus(corpus_path: Path | str, report_path: Path | str) -> dict[str, Any]:
    corpus = load_production_corpus(corpus_path)
    report = load_report(Path(report_path))
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
        "malicious_allow_rate": summary["malicious_allow_rate"] <= thresholds["max_malicious_allow_rate"],
        "incomplete_required": summary["incomplete_required"] <= thresholds["max_incomplete_required"],
    }
    gate_passed = all(gate_checks.values())
    return {
        "schema_version": PRODUCTION_CORPUS_SCHEMA_VERSION,
        "corpus_id": corpus["corpus_id"],
        "corpus_version": corpus.get("corpus_version", "unknown"),
        "report_identity": {
            key: report.get(key) or (report.get("metadata") or {}).get(key)
            for key in ("scanner_build", "policy_version", "ruleset_version")
        },
        "gate": {
            "passed": gate_passed,
            "checks": gate_checks,
            "thresholds": thresholds,
        },
        "summary": summary,
        "artifacts": rows,
    }


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
    malicious_allows = sum(1 for row in malicious if row["actual"].get("decision") == "allow")
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
        "malicious_evaluated": len(malicious),
        "malicious_allows": malicious_allows,
        "malicious_allow_rate": round(malicious_allows / len(malicious), 4) if malicious else 0.0,
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
