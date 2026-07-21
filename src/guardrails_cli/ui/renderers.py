from __future__ import annotations

import textwrap
from typing import Any

from guardrails_cli import __version__

from .panels import banner, panel, section
from .tables import key_values, table, terminal_width, truncate
from .theme import color, severity_label, severity_style, verdict_style


DECISION_RANK = {"block": 4, "incomplete": 3, "review": 2, "allow": 1}
SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def render_scan_report(report: dict[str, Any], *, show_all: bool = False) -> str:
    extensions = [item for item in report.get("extensions", []) if isinstance(item, dict)]
    summary = dict(report.get("summary") or {})
    metadata = dict(report.get("metadata") or {})
    counts = _decision_counts(summary, extensions)
    overall = max((_decision(item) for item in extensions), key=lambda value: DECISION_RANK[value], default="incomplete")
    completed = len(extensions) - counts["incomplete"]
    profile = str(metadata.get("profile") or "recorded")
    source = str(metadata.get("source") or "local")

    lines = [banner("Installed extension scan" if source == "installed" else "Extension scan")]
    lines.append(_outcome_panel(overall, counts, summary, total=len(extensions), completed=completed, profile=profile))

    if len(extensions) == 1:
        lines.append(render_extension_detail(extensions[0], include_outcome=False))
    elif extensions:
        lines.append(render_extension_summary(extensions, show_all=show_all))
    else:
        lines.append(panel("No result", "The report does not contain an extension result.", subtitle="INCOMPLETE"))

    lines.append(_metadata_footer(report, metadata))
    return "\n".join(line for line in lines if line)


def _outcome_panel(overall: str, counts: dict[str, int], summary: dict[str, Any], *, total: int, completed: int, profile: str) -> str:
    label = color(overall.upper(), verdict_style(overall))
    distribution = "   ".join(
        color(f"{decision.upper()} {counts[decision]}", verdict_style(decision))
        for decision in ("block", "incomplete", "review", "allow")
    )
    risk = int(summary.get("max_risk_score") or 0)
    malware = int(summary.get("max_malware_score") or 0)
    next_action = {
        "block": "Do not use blocked extensions until the recorded evidence is resolved.",
        "incomplete": "Required analysis did not finish. Fix provider or artifact errors and scan again.",
        "review": "Review the highest-priority evidence against the extension's expected purpose.",
        "allow": "No decision-level evidence requires action. This result applies only to the scanned artifacts.",
    }[overall]
    body = "\n".join([
        f"{label}  ·  {completed}/{total} complete  ·  {profile} profile",
        distribution,
        f"Priority indexes  risk {risk}/100  ·  malware evidence {malware}/100",
        "",
        next_action,
    ])
    return panel("Scan outcome", body, subtitle="action first")


def render_extension_summary(extensions: list[dict[str, Any]], *, show_all: bool = False) -> str:
    ranked = _rank_extensions(extensions)
    actionable = [item for item in ranked if _decision(item) != "allow"]
    candidates = ranked if show_all else actionable
    visible = candidates if show_all else candidates[:12]
    lines = [section("Action required" if actionable else "Results")]
    if not actionable and not show_all:
        lines.append(color(f"No BLOCK, INCOMPLETE, or REVIEW decisions. {len(extensions)} installation(s) are ALLOW.", "green"))
        lines.append(color("Use --show-all to include ALLOW rows.", "gray"))
        return "\n".join(lines)
    for extension in visible:
        lines.extend(_result_row(extension))
    hidden = len(candidates) - len(visible)
    if hidden:
        lines.append(color(f"{hidden} more actionable result(s) omitted. Use --show-all for the complete terminal list.", "gray"))
    allow_count = sum(_decision(item) == "allow" for item in extensions)
    if allow_count and not show_all:
        lines.append(color(f"ALLOW results hidden by default: {allow_count}", "gray"))
    return "\n".join(lines)


def _result_row(extension: dict[str, Any]) -> list[str]:
    width = terminal_width()
    decision = _decision(extension)
    identity = f"{extension.get('extension_id', 'unknown')}@{extension.get('version', 'unknown')}"
    client = _client(extension)
    reason = str(extension.get("decision_reason") or extension.get("verdict_reason") or "No decision explanation was recorded.")
    if width < 60:
        lines = [f"{color(decision.upper(), verdict_style(decision))}  {color(client, 'gray')}", f"  {truncate(identity, max(12, width - 2))}"]
        indent = "  "
    else:
        prefix = color(f"{decision.upper():<10}", verdict_style(decision))
        lines = [f"{prefix} {truncate(identity, max(20, width - 28))}  {color(client, 'gray')}"]
        indent = " " * 11
    lines.extend(indent + part for part in _wrap(reason, max(16, width - len(indent))))
    facts = f"coverage {_coverage(extension)}% · risk {int(extension.get('risk_score') or 0)}/100 · {len(extension.get('findings') or [])} finding(s)"
    lines.append(indent + color(truncate(facts, max(12, width - len(indent))), "gray"))
    lines.append("")
    return lines


def render_extension_detail(extension: dict[str, Any], *, include_outcome: bool = True) -> str:
    decision = _decision(extension)
    artifact_identity = extension.get("artifact_identity") if isinstance(extension.get("artifact_identity"), dict) else {}
    artifact_sha = str(extension.get("artifact_sha256") or artifact_identity.get("sha256") or extension.get("artifact_hash") or "unavailable")
    reason = str(extension.get("decision_reason") or extension.get("verdict_reason") or "No decision explanation was recorded.")
    lines = [section(str(extension.get("name") or extension.get("extension_id") or "Extension"))]
    if include_outcome:
        lines.append(f"{color(decision.upper(), verdict_style(decision))}  {extension.get('extension_id', 'unknown')}@{extension.get('version', 'unknown')}")
    lines.extend(_wrap(reason, terminal_width()))
    lines.append("")
    lines.append(key_values([
        ("Extension", extension.get("extension_id", "unknown")),
        ("Version", extension.get("version", "unknown")),
        ("IDE", _client(extension)),
        ("Severity", _severity_text(str(extension.get("severity") or "INFO"))),
        ("Coverage", f"{_coverage(extension)}%"),
        ("Risk", f"{int(extension.get('risk_score') or 0)}/100"),
        ("Malware evidence", f"{int(extension.get('malware_score') or 0)}/100"),
        ("Artifact SHA-256", artifact_sha),
    ]))
    lines.append(render_provider_coverage(extension))
    findings = [item for item in extension.get("findings", []) if isinstance(item, dict)]
    lines.append(render_findings(findings) if findings else section("Evidence") + "\n" + color("No findings were reported.", "green"))
    return "\n".join(line for line in lines if line)


def render_provider_coverage(extension: dict[str, Any]) -> str:
    coverage = extension.get("analysis_coverage") if isinstance(extension.get("analysis_coverage"), dict) else {}
    providers = coverage.get("providers") if isinstance(coverage.get("providers"), dict) else {}
    lines = [section("Analysis coverage")]
    if not providers:
        lines.extend(color(part, "gray") for part in _wrap(f"{_coverage(extension)}% · provider detail unavailable", terminal_width()))
        return "\n".join(lines)
    for provider, detail in providers.items():
        item = detail if isinstance(detail, dict) else {}
        status = str(item.get("status") or "unknown")
        required = "required" if item.get("required") else "optional"
        style = "green" if status == "completed" else "red" if required == "required" else "yellow"
        label = {"dependency_intelligence": "dependency advisories", "javascript_ast": "JavaScript AST", "native_static": "native static"}.get(provider, provider.replace("_", " "))
        lines.append(f"{color('●', style)}  {label:<24} {color(status, style)}  {color(required, 'gray')}")
    return "\n".join(lines)


def render_findings(findings: list[dict[str, Any]]) -> str:
    ranked = sorted(findings, key=lambda item: (SEVERITY_RANK.get(str(item.get("severity") or "INFO").upper(), 0), _confidence(item.get("confidence"))), reverse=True)
    lines = [section("Highest-priority evidence")]
    for finding in ranked[:10]:
        severity = str(finding.get("severity") or "INFO")
        rule = str(finding.get("rule_id") or "unknown-rule")
        summary = str(finding.get("evidence_summary") or "No summary recorded.")
        evidence_class = str(finding.get("evidence_class") or _evidence_class(finding))
        refs = [str(value) for value in finding.get("file_refs", []) if value]
        lines.append(f"{_severity_text(severity):<12} {truncate(rule, max(12, terminal_width() - 14))}")
        lines.extend("  " + part for part in _wrap(summary, max(16, terminal_width() - 2)))
        detail = evidence_class + (f" · {refs[0]}" if refs else "")
        lines.append("  " + color(truncate(detail, max(12, terminal_width() - 2)), "gray"))
        lines.append("")
    if len(ranked) > 10:
        lines.append(color(f"{len(ranked) - 10} more finding(s) are available in exported report data.", "gray"))
    return "\n".join(lines).rstrip()


def render_rules(rules: list[dict[str, Any]], *, limit: int = 40) -> str:
    rows = [[rule.get("rule_id", ""), rule.get("category", ""), _severity_text(str(rule.get("default_severity") or "")), rule.get("evidence_class", ""), rule.get("title", "")] for rule in rules[:limit]]
    return table(["Rule", "Category", "Severity", "Class", "Title"], rows, max_widths=[34, 22, 12, 14, 42])


def _metadata_footer(report: dict[str, Any], metadata: dict[str, Any]) -> str:
    scan_id = metadata.get("scan_id") or report.get("scan_id", "unknown")
    created = metadata.get("created_at") or report.get("created_at", "n/a") or "n/a"
    engine = metadata.get("scanner_version") or "unknown"
    build = str(metadata.get("scanner_build") or "unknown")
    ruleset = metadata.get("ruleset_version") or "unknown"
    cli = metadata.get("cli_version") or __version__
    body = f"Scan {scan_id} · {created}\nEngine {engine} ({build[:12]}) · rules {ruleset} · CLI {cli}\nFiles remain local unless you explicitly export or upload."
    return color(truncate(body.splitlines()[0], terminal_width()), "gray") + "\n" + "\n".join(color(truncate(line, terminal_width()), "gray") for line in body.splitlines()[1:])


def _wrap(value: str, width: int) -> list[str]:
    return textwrap.wrap(value, width=max(12, width), break_long_words=True, break_on_hyphens=False) or [""]


def _decision_counts(summary: dict[str, Any], extensions: list[dict[str, Any]]) -> dict[str, int]:
    recorded = summary.get("decision_counts") if isinstance(summary.get("decision_counts"), dict) else None
    if recorded and sum(int(recorded.get(decision) or 0) for decision in DECISION_RANK) == len(extensions):
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
    return {"vscode": "VS Code", "vscode-insiders": "VS Code Insiders", "cursor": "Cursor", "windsurf": "Windsurf", "vscodium": "VSCodium"}.get(value.lower(), value)


def _rank_extensions(extensions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(extensions, key=lambda item: (DECISION_RANK.get(_decision(item), 0), int(item.get("malware_score") or 0), int(item.get("risk_score") or 0), str(item.get("extension_id") or "")), reverse=True)


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
