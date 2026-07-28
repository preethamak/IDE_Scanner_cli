from __future__ import annotations

import datetime as dt
import json
import zipfile
from pathlib import Path
from typing import Any

BENCHMARK_SCHEMA_VERSION = "1.0"
EXPOSURE_CATEGORY = "cross-extension-exposure"


def run_credential_exposure_benchmark(dataset_path: Path | str, report_path: Path | str) -> dict[str, Any]:
    dataset = _load_json(Path(dataset_path))
    report = load_report(Path(report_path))
    extensions = _report_extensions(report)
    rows = [_evaluate_extension(expected, extensions.get(str(expected.get("extension_id") or ""))) for expected in dataset.get("extensions", [])]
    summary = _benchmark_summary(dataset, rows)
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "metadata": _metadata(dataset, report, rows),
        "leaderboard": {"extensions": rows},
        "benchmark_summary": summary,
        "rule_coverage": _rule_coverage(rows),
        "comparisons": {
            "compared_tools": [],
            "note": "No external comparison tool outputs were provided.",
        },
        "extensions": {row["extension_id"]: row for row in rows},
    }


def write_benchmark_bundle(result: dict[str, Any], output: Path | str) -> dict[str, Any]:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        _write_json(archive, "metadata.json", result.get("metadata") or {})
        _write_json(archive, "leaderboard.json", result.get("leaderboard") or {})
        _write_json(archive, "benchmark_summary.json", result.get("benchmark_summary") or {})
        _write_json(archive, "rule_coverage.json", result.get("rule_coverage") or {})
        _write_json(archive, "comparisons.json", result.get("comparisons") or {})
        for extension_id, row in sorted((result.get("extensions") or {}).items()):
            _write_json(archive, f"extensions/{_safe_name(extension_id)}.json", row)
    return {
        "output": str(output_path),
        "metadata": result.get("metadata") or {},
        "benchmark_summary": result.get("benchmark_summary") or {},
    }


def load_report(path: Path) -> dict[str, Any]:
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            if "leaderboard.json" not in names:
                raise ValueError("Report bundle is missing leaderboard.json")
            leaderboard = json.loads(archive.read("leaderboard.json"))
            extensions: list[dict[str, Any]] = []
            for row in leaderboard.get("extensions") or []:
                if not isinstance(row, dict):
                    continue
                detail_ref = str(row.get("detail_ref") or "")
                detail = {}
                if detail_ref and detail_ref in names:
                    detail = json.loads(archive.read(detail_ref))
                merged = dict(row)
                merged.update(detail if isinstance(detail, dict) else {})
                extensions.append(merged)
            return {
                "schema_version": "2.0",
                "metadata": json.loads(archive.read("metadata.json")) if "metadata.json" in names else {},
                "extensions": extensions,
            }
    return _load_json(path)


def _evaluate_extension(expected: dict[str, Any], actual: dict[str, Any] | None) -> dict[str, Any]:
    extension_id = str(expected.get("extension_id") or "")
    expected_findings = [str(item) for item in expected.get("expected_findings") or []]
    expected_positive = str(expected.get("label") or "") == "credential_exposure"
    if actual is None:
        return {
            "extension_id": extension_id,
            "version": str(expected.get("version") or "unknown"),
            "label": str(expected.get("label") or ""),
            "exposure_types": list(expected.get("exposure_types") or []),
            "expected_findings": expected_findings,
            "ide_scanner_findings": [],
            "matched_findings": [],
            "matched": False,
            "outcome": "not_scanned",
            "severity": "missing",
            "verdict": "missing",
            "risk_score": None,
            "malware_score": None,
            "evidence": [],
            "not_reported_by_compared_tools": [],
            "reference": str(expected.get("reference") or ""),
        }
    actual_findings = _actual_finding_ids(actual)
    matched_findings = sorted(set(expected_findings) & actual_findings)
    actual_positive = _has_exposure_finding(actual)

    if expected_positive and actual_positive:
        outcome = "true_positive"
    elif expected_positive:
        outcome = "false_negative"
    elif actual_positive:
        outcome = "false_positive"
    else:
        outcome = "true_negative"

    matched = bool(matched_findings) if expected_positive and expected_findings else actual_positive == expected_positive
    return {
        "extension_id": extension_id,
        "version": str(expected.get("version") or (actual or {}).get("version") or "unknown"),
        "label": str(expected.get("label") or ""),
        "exposure_types": list(expected.get("exposure_types") or []),
        "expected_findings": expected_findings,
        "ide_scanner_findings": sorted(actual_findings),
        "matched_findings": matched_findings,
        "matched": matched,
        "outcome": outcome,
        "severity": str((actual or {}).get("severity") or "missing"),
        "verdict": str((actual or {}).get("verdict") or "missing"),
        "risk_score": (actual or {}).get("risk_score"),
        "malware_score": (actual or {}).get("malware_score"),
        "evidence": _evidence_summaries(actual),
        "not_reported_by_compared_tools": [],
        "reference": str(expected.get("reference") or ""),
    }


def _benchmark_summary(dataset: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = [row for row in rows if row["outcome"] != "not_scanned"]
    tp = sum(1 for row in evaluated if row["outcome"] == "true_positive")
    fp = sum(1 for row in evaluated if row["outcome"] == "false_positive")
    fn = sum(1 for row in evaluated if row["outcome"] == "false_negative")
    tn = sum(1 for row in evaluated if row["outcome"] == "true_negative")
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    return {
        "dataset_id": dataset.get("dataset_id"),
        "source": dataset.get("source"),
        "total_extensions": len(rows),
        "evaluated_extensions": len(evaluated),
        "not_scanned": len(rows) - len(evaluated),
        "credential_extension_count": sum(1 for row in rows if row["label"] == "credential_exposure"),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "unique_signals": len({finding for row in rows for finding in row["ide_scanner_findings"]}),
    }


def _rule_coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    expected_rules = sorted({rule for row in rows for rule in row["expected_findings"]})
    coverage = []
    for rule_id in expected_rules:
        expected = [row for row in rows if rule_id in row["expected_findings"]]
        detected = [row for row in expected if rule_id in row["ide_scanner_findings"]]
        false_positives = [
            row for row in rows
            if rule_id in row["ide_scanner_findings"] and rule_id not in row["expected_findings"]
        ]
        precision = len(detected) / (len(detected) + len(false_positives)) if detected or false_positives else 0
        recall = len(detected) / len(expected) if expected else 0
        coverage.append({
            "rule_id": rule_id,
            "expected": len(expected),
            "detections": len(detected),
            "false_positives": len(false_positives),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
        })
    return {"rules": coverage}


def _metadata(dataset: dict[str, Any], report: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    report_metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "benchmark_id": f"benchmark_{dt.datetime.now(dt.UTC).strftime('%Y%m%d%H%M%S')}",
        "created_at": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
        "dataset_id": dataset.get("dataset_id"),
        "dataset_source": dataset.get("source"),
        "scanner_version": report_metadata.get("scanner_version", ""),
        "ruleset_version": report_metadata.get("ruleset_version", ""),
        "scan_id": report_metadata.get("scan_id", ""),
        "total_extensions": len(rows),
    }


def _report_extensions(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("extension_id")): item
        for item in report.get("extensions", [])
        if isinstance(item, dict) and item.get("extension_id")
    }


def _actual_finding_ids(actual: dict[str, Any] | None) -> set[str]:
    if not actual:
        return set()
    return {
        str(finding.get("rule_id"))
        for finding in actual.get("findings", [])
        if isinstance(finding, dict) and finding.get("rule_id")
    }


def _has_exposure_finding(actual: dict[str, Any] | None) -> bool:
    if not actual:
        return False
    for finding in actual.get("findings", []):
        if not isinstance(finding, dict):
            continue
        if finding.get("category") == EXPOSURE_CATEGORY:
            return True
        evidence_class = str(finding.get("evidence_class") or (finding.get("evidence") or {}).get("evidence_class") or "")
        if evidence_class == "exposure":
            return True
    return False


def _evidence_summaries(actual: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not actual:
        return []
    out: list[dict[str, Any]] = []
    for finding in actual.get("findings", []):
        if not isinstance(finding, dict) or finding.get("category") != EXPOSURE_CATEGORY:
            continue
        out.append({
            "rule_id": finding.get("rule_id"),
            "severity": finding.get("severity"),
            "summary": finding.get("evidence_summary"),
            "file_refs": list(finding.get("file_refs") or [])[:5],
        })
    return out[:20]


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _write_json(archive: zipfile.ZipFile, name: str, data: Any) -> None:
    archive.writestr(name, json.dumps(data, indent=2, sort_keys=True) + "\n")


def _safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-@" else "_" for char in value)[:160] or "unknown"
