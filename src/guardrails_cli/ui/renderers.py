from __future__ import annotations

from typing import Any

from guardrails_cli import __version__

from .panels import banner, panel, section
from .tables import key_values, score_bar, table, terminal_width, truncate
from .theme import color, severity_label, severity_style, verdict_style


DECISION_RANK = {"block": 4, "incomplete": 3, "review": 2, "allow": 1}
SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def render_scan_report(report: dict[str, Any], *, show_all: bool = False) -> str:
    extensions = [item for item in report.get("extensions", []) if isinstance(item, dict)]
    summary = dict(report.get("summary") or {})
    metadata = dict(report.get("metadata") or {})
    counts = _decision_counts(summary, extensions)
    completed = len(extensions) - counts["incomplete"]
    lines = [
        banner("Local IDE extension scanner"),
        panel(
            "Scan result",
            key_values([
                ("Scan ID", metadata.get("scan_id") or report.get("scan_id", "unknown")),
                ("Extensions", len(extensions)),
                ("Complete", completed),
                ("Incomplete", counts["incomplete"]),
                ("Created", metadata.get("created_at") or report.get("created_at", "n/a") or "n/a"),
            ]),
            subtitle="local report",
        ),
        render_decision_summary(counts, summary),
    ]
    if len(extensions) > 1:
        lines.append(render_extension_summary_table(extensions, show_all=show_all))
        if not show_all and len(extensions) > 15:
            lines.append(color(f"Showing the 15 highest-priority installations. Use --all to print every row.", "gray"))
    elif extensions:
        lines.append(render_extension_detail(extensions[0]))
    else:
        lines.append(panel("No extensions", "The report does not contain an extension result.", subtitle="incomplete"))
    lines.append(color(truncate(f"Guardrails v{__version__} · files remain local unless you explicitly export or upload", terminal_width()), "gray"))
    return "\n".join(line for line in lines if line)


def render_decision_summary(counts: dict[str, int], summary: dict[str, Any]) -> str:
    rows = []
    for decision in ("block", "review", "incomplete", "allow"):
        rows.append([color(decision.upper(), verdict_style(decision)), counts[decision]])
    risk = int(summary.get("max_risk_score") or 0)
    malware = int(summary.get("max_malware_score") or 0)
    body = table(["Decision", "Installations"], rows, max_widths=[18, 14])
    body += "\n\n" + key_values([
        ("Highest risk", score_bar(risk, width=24)),
        ("Malware evidence", score_bar(malware, width=24)),
    ])
    return panel("Overview", body)


def render_extension_summary_table(extensions: list[dict[str, Any]], *, show_all: bool = False) -> str:
    ranked = _rank_extensions(extensions)
    visible = ranked if show_all else ranked[:15]
    rows = []
    for index, extension in enumerate(visible, start=1):
        decision = _decision(extension)
        rows.append([
            index,
            _client(extension),
            f"{extension.get('extension_id', 'unknown')}@{extension.get('version', 'unknown')}",
            color(decision.upper(), verdict_style(decision)),
            _coverage(extension),
            extension.get("risk_score", 0),
            len(extension.get("findings") or []),
        ])
    return section("Installed extensions") + "\n" + table(
        ["#", "IDE", "Extension", "Decision", "Coverage", "Risk", "Findings"],
        rows,
        max_widths=[4, 14, 42, 12, 10, 7, 9],
    )


def render_extension_detail(extension: dict[str, Any]) -> str:
    decision = _decision(extension)
    artifact_identity = extension.get("artifact_identity") if isinstance(extension.get("artifact_identity"), dict) else {}
    artifact_sha = str(extension.get("artifact_sha256") or artifact_identity.get("sha256") or extension.get("artifact_hash") or "unavailable")
    reason = str(extension.get("decision_reason") or extension.get("verdict_reason") or "No decision explanation was recorded.")
    body = key_values([
        ("Extension", extension.get("extension_id", "unknown")),
        ("Version", extension.get("version", "unknown")),
        ("IDE", _client(extension)),
        ("Decision", color(decision.upper(), verdict_style(decision))),
        ("Severity", _severity_text(str(extension.get("severity") or "INFO"))),
        ("Coverage", f"{_coverage(extension)}%"),
        ("Artifact SHA", artifact_sha),
        ("Risk", score_bar(int(extension.get("risk_score") or 0), width=24)),
        ("Malware evidence", score_bar(int(extension.get("malware_score") or 0), width=24)),
    ])
    lines = [section(str(extension.get("name") or extension.get("extension_id") or "Extension")), body]
    lines.append(panel("Why this result", reason, subtitle=decision.upper()))
    lines.append(render_provider_coverage(extension))
    findings = [item for item in extension.get("findings", []) if isinstance(item, dict)]
    if findings:
        lines.append(render_findings(findings))
    else:
        lines.append(color("No findings were reported.", "green"))
    return "\n".join(line for line in lines if line)


def render_provider_coverage(extension: dict[str, Any]) -> str:
    coverage = extension.get("analysis_coverage") if isinstance(extension.get("analysis_coverage"), dict) else {}
    providers = coverage.get("providers") if isinstance(coverage.get("providers"), dict) else {}
    if not providers:
        return panel("Analysis coverage", f"Coverage {_coverage(extension)}% · provider detail unavailable", subtitle="recorded result")
    rows = []
    for provider, detail in providers.items():
        item = detail if isinstance(detail, dict) else {}
        status = str(item.get("status") or "unknown")
        required = "required" if item.get("required") else "optional"
        style = "green" if status == "completed" else "red" if required == "required" else "yellow"
        label = {
            "dependency_intelligence": "dependency advisories",
            "javascript_ast": "javascript ast",
            "native_static": "native static",
        }.get(provider, provider.replace("_", " "))
        rows.append([label, color(status, style), required])
    return panel("Analysis coverage", table(["Provider", "Status", "Policy"], rows, max_widths=[30, 16, 12]), subtitle=f"{_coverage(extension)}%")


def render_findings(findings: list[dict[str, Any]]) -> str:
    ranked = sorted(findings, key=lambda item: (SEVERITY_RANK.get(str(item.get("severity") or "INFO").upper(), 0), _confidence(item.get("confidence"))), reverse=True)
    rows = []
    for finding in ranked[:10]:
        rows.append([
            _severity_text(str(finding.get("severity") or "INFO")),
            finding.get("rule_id", ""),
            finding.get("evidence_class") or _evidence_class(finding),
            finding.get("evidence_summary", ""),
        ])
    output = section("Highest-priority evidence") + "\n" + table(
        ["Severity", "Rule", "Class", "Summary"], rows, max_widths=[10, 34, 14, 58]
    )
    if len(ranked) > 10:
        output += "\n" + color(f"{len(ranked) - 10} more finding(s) are available in the full report.", "gray")
    return output


def render_rules(rules: list[dict[str, Any]], *, limit: int = 40) -> str:
    rows = []
    for rule in rules[:limit]:
        rows.append([
            rule.get("rule_id", ""),
            rule.get("category", ""),
            _severity_text(str(rule.get("default_severity") or "")),
            rule.get("evidence_class", ""),
            rule.get("title", ""),
        ])
    return table(["Rule", "Category", "Severity", "Class", "Title"], rows, max_widths=[34, 22, 10, 14, 42])


def _decision_counts(summary: dict[str, Any], extensions: list[dict[str, Any]]) -> dict[str, int]:
    recorded = summary.get("decision_counts") if isinstance(summary.get("decision_counts"), dict) else None
    if recorded:
        return {decision: int(recorded.get(decision) or 0) for decision in DECISION_RANK}
    counts = {decision: 0 for decision in DECISION_RANK}
    for extension in extensions:
        counts[_decision(extension)] += 1
    return counts


def _decision(extension: dict[str, Any]) -> str:
    value = str(extension.get("decision") or "").lower()
    if value in DECISION_RANK:
        return value
    verdict = str(extension.get("verdict") or "").lower()
    return {"clean": "allow", "review": "review", "suspicious": "review", "malicious": "block"}.get(verdict, "incomplete")


def _coverage(extension: dict[str, Any]) -> int:
    if extension.get("coverage_percent") is not None:
        return int(extension.get("coverage_percent") or 0)
    coverage = extension.get("analysis_coverage") if isinstance(extension.get("analysis_coverage"), dict) else {}
    return int(coverage.get("coverage_percent") or 0)


def _client(extension: dict[str, Any]) -> str:
    value = str(extension.get("client") or extension.get("ide") or extension.get("source") or "local")
    return {
        "vscode": "VS Code",
        "vscode-insiders": "VS Code Insiders",
        "cursor": "Cursor",
        "windsurf": "Windsurf",
        "vscodium": "VSCodium",
    }.get(value.lower(), value)


def _rank_extensions(extensions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        extensions,
        key=lambda item: (
            DECISION_RANK.get(_decision(item), 0),
            int(item.get("malware_score") or 0),
            int(item.get("risk_score") or 0),
            str(item.get("extension_id") or ""),
        ),
        reverse=True,
    )


def _severity_text(severity: str) -> str:
    return color(severity_label(severity), severity_style(severity))


def _evidence_class(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    return str(evidence.get("evidence_class") or "unknown")


def _confidence(value: object) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return {"low": 0.3, "medium": 0.6, "high": 0.9}.get(str(value).lower(), 0)
