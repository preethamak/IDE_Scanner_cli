from __future__ import annotations

from pathlib import Path
from typing import Any

from ._atomic import write_text


def export_markdown(report: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    write_text(path, to_markdown(report))
    return path


def to_markdown(report: dict[str, Any]) -> str:
    summary = dict(report.get("summary") or {})
    metadata = dict(report.get("metadata") or {})
    extensions = [item for item in report.get("extensions", []) if isinstance(item, dict)]
    counts = _counts(summary, extensions)
    overall = next((decision for decision in ("block", "incomplete", "review", "allow") if counts[decision]), "incomplete")
    next_action = {
        "block": "Disable the blocked extensions and review the evidence before restoring them.",
        "incomplete": "Resolve incomplete provider coverage, then scan again before making a trust decision.",
        "review": "Review the highlighted evidence before keeping these extensions enabled.",
        "allow": "No action is required for this scan.",
    }[overall]
    lines = [
        "# Guardrails local extension report",
        "",
        f"## Outcome: {overall.upper()}",
        "",
        next_action,
        "",
        "## Decisions",
        "",
        "| Allow | Review | Block | Incomplete |",
        "| ---: | ---: | ---: | ---: |",
        f"| {counts['allow']} | {counts['review']} | {counts['block']} | {counts['incomplete']} |",
        "",
    ]
    for extension in sorted(extensions, key=_priority, reverse=True):
        lines.extend(_extension_markdown(extension))
    lines.extend(
        [
            "## Scan identity",
            "",
            f"- Scan ID: `{metadata.get('scan_id') or report.get('scan_id', 'unknown')}`",
            f"- Created: {metadata.get('created_at') or report.get('created_at', 'unknown')}",
            f"- Scanner: `{metadata.get('scanner_version', 'unknown')}`",
            f"- Scanner build: `{metadata.get('scanner_build', 'unknown')}`",
            f"- Ruleset: `{metadata.get('ruleset_version', 'unknown')}`",
            f"- Extensions: {len(extensions)}",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _extension_markdown(extension: dict[str, Any]) -> list[str]:
    decision = _decision(extension)
    coverage = extension.get("analysis_coverage") if isinstance(extension.get("analysis_coverage"), dict) else {}
    artifact = extension.get("artifact_identity") if isinstance(extension.get("artifact_identity"), dict) else {}
    sha = extension.get("artifact_sha256") or artifact.get("sha256") or extension.get("artifact_hash") or "unavailable"
    lines = [
        f"## {_clean(extension.get('extension_id', 'unknown'))}@{_clean(extension.get('version', 'unknown'))}",
        "",
        f"- IDE: {_clean(_ide_label(extension.get('client') or extension.get('source') or 'local'))}",
        f"- Decision: **{decision.upper()}**",
        f"- Severity: {_clean(extension.get('severity', 'INFO'))}",
        f"- Coverage: {int(extension.get('coverage_percent') if extension.get('coverage_percent') is not None else coverage.get('coverage_percent') or 0)}%",
        f"- Artifact SHA-256: `{_clean(sha)}`",
        f"- Risk: {int(extension.get('risk_score') or 0)}/100",
        f"- Malware evidence: {int(extension.get('malware_score') or 0)}/100",
        "",
        "### Why this result",
        "",
        _clean(extension.get("decision_reason") or extension.get("verdict_reason") or "No explanation was recorded."),
        "",
        "### Findings",
        "",
        "| Severity | Rule | Evidence | Summary |",
        "| --- | --- | --- | --- |",
    ]
    findings = [item for item in extension.get("findings", []) if isinstance(item, dict)]
    if not findings:
        lines.append("| - | - | - | No findings reported |")
    for finding in findings:
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        lines.append(
            "| {severity} | `{rule}` | {klass} | {summary} |".format(
                severity=_clean(finding.get("severity", "")),
                rule=_clean(finding.get("rule_id", "")),
                klass=_clean(finding.get("evidence_class") or evidence.get("evidence_class") or "unknown"),
                summary=_clean(finding.get("evidence_summary", "")),
            )
        )
    lines.append("")
    return lines


def _counts(summary: dict[str, Any], extensions: list[dict[str, Any]]) -> dict[str, int]:
    recorded = summary.get("decision_counts") if isinstance(summary.get("decision_counts"), dict) else None
    if recorded:
        return {key: int(recorded.get(key) or 0) for key in ("allow", "review", "block", "incomplete")}
    result = {key: 0 for key in ("allow", "review", "block", "incomplete")}
    for extension in extensions:
        result[_decision(extension)] += 1
    return result


def _decision(extension: dict[str, Any]) -> str:
    value = str(extension.get("decision") or "").lower()
    if value in {"allow", "review", "block", "incomplete"}:
        return value
    return {"clean": "allow", "review": "review", "suspicious": "review", "malicious": "block"}.get(str(extension.get("verdict") or "").lower(), "incomplete")


def _priority(extension: dict[str, Any]) -> tuple[int, int, int]:
    return ({"allow": 1, "review": 2, "incomplete": 3, "block": 4}[_decision(extension)], int(extension.get("malware_score") or 0), int(extension.get("risk_score") or 0))


def _clean(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("`", "\\`")


def _ide_label(value: object) -> str:
    label = str(value)
    return {"vscode": "VS Code", "vscode-insiders": "VS Code Insiders", "cursor": "Cursor", "windsurf": "Windsurf", "vscodium": "VSCodium"}.get(label.lower(), label)
