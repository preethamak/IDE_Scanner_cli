#!/usr/bin/env python3
"""Publish a GuardRails report as safe GitHub Actions outputs and Markdown."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


DECISION_ORDER = {"allow": 0, "review": 1, "block": 2, "incomplete": 3}


def report_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Reduce the canonical report to stable CI-facing decision facts."""
    extensions = [item for item in report.get("extensions", []) if isinstance(item, dict)]
    decisions = [str(item.get("decision") or "incomplete").lower() for item in extensions]
    decision = max(decisions, key=lambda item: DECISION_ORDER.get(item, 3), default="incomplete")
    counts = {name: decisions.count(name) for name in DECISION_ORDER}
    coverage = [item.get("analysis_coverage") for item in extensions if isinstance(item.get("analysis_coverage"), dict)]
    complete = bool(extensions) and all(str(item.get("status") or "complete").lower() == "complete" and str(item.get("analysis_coverage", {}).get("status") or "complete").lower() == "complete" for item in extensions)
    return {
        "decision": decision,
        "extension_count": len(extensions),
        "allow_count": counts["allow"],
        "review_count": counts["review"],
        "block_count": counts["block"],
        "incomplete_count": counts["incomplete"],
        "complete": complete,
        "coverage_percent": min((float(item.get("coverage_percent") or 0) for item in coverage), default=0),
        "extensions": extensions,
    }


def write_github_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value.replace(chr(10), ' ').replace(chr(13), ' ')}\n")


def markdown(summary: dict[str, Any], report_path: str, scan_exit_code: int) -> str:
    status = "passed" if scan_exit_code == 0 else "requires attention"
    rows = [
        "| Field | Value |",
        "| --- | --- |",
        f"| CI status | {status} |",
        f"| Decision | {summary['decision'].upper()} |",
        f"| Extensions | {summary['extension_count']} |",
        f"| Coverage floor | {summary['coverage_percent']:.0f}% |",
        f"| Complete analysis | {'yes' if summary['complete'] else 'no'} |",
        f"| Evidence artifact | `{report_path}` |",
    ]
    for extension in summary["extensions"][:20]:
        identity = extension.get("artifact_identity") if isinstance(extension.get("artifact_identity"), dict) else {}
        sha256 = str(identity.get("sha256") or "")
        extension_id = str(extension.get("extension_id") or "unknown")
        version = str(extension.get("version") or "unknown")
        rows.append(f"- **{extension_id}@{version}**: {str(extension.get('decision') or 'incomplete').upper()}{f' (SHA-256 {sha256[:12]}...)' if sha256 else ''}")
    return "## GuardRails extension review\n\n" + "\n".join(rows) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--scan-exit-code", type=int, required=True)
    args = parser.parse_args()
    report_path = Path(args.report)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("report root must be an object")
        summary = report_summary(report)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        summary = {"decision": "incomplete", "extension_count": 0, "allow_count": 0, "review_count": 0, "block_count": 0, "incomplete_count": 1, "complete": False, "coverage_percent": 0, "extensions": []}
        report_error = str(exc)
    else:
        report_error = ""

    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        write_github_output(Path(output_path), {
            "decision": str(summary["decision"]),
            "extension-count": str(summary["extension_count"]),
            "coverage-percent": f"{summary['coverage_percent']:.0f}",
            "complete": str(summary["complete"]).lower(),
            "report-valid": str(not report_error).lower(),
        })
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write(markdown(summary, args.report, args.scan_exit_code))
            if report_error:
                handle.write(f"\nReport could not be read: {report_error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
