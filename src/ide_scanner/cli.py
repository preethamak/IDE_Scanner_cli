from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .agent import build_agent_report, upload_agent_report
from .benchmarks.adapters.protect_your_secrets import write_normalized_dataset
from .benchmarks.runner import run_credential_exposure_benchmark, write_benchmark_bundle
from .discovery import discover_from_path, discover_local_installations
from .report_bundle import iter_report_events, write_report_bundle
from .sandbox_runner import run_sandbox
from .scanner import scan_targets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ide-scanner", description="Scan VS Code-compatible extensions for security risk.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a security scan.")
    scan.add_argument("--fixtures", action="store_true", help="Scan bundled sample extensions.")
    scan.add_argument("--all", "--installed", dest="installed", action="store_true", help="Scan local VS Code-compatible extension installs.")
    scan.add_argument("--path", "--folder", "--vsix", dest="path", action="append", default=[], help="Extension folder, extensions directory, or VSIX file to scan.")
    scan.add_argument("--extension-id", "--marketplace", dest="extension_id", action="append", default=[], help="Extension identifier to check against online registries.")
    scan.add_argument("--version", help="Pin one Marketplace extension scan to an exact published version.")
    scan.add_argument("--profile", choices=["quick", "standard", "deep", "smart", "benchmark"], default="smart", help="Report label recorded in the bundle. Analysis depth is identical across profiles; only 'deep' additionally enables online registry checks (same as --online).")
    scan.add_argument("--format", choices=["terminal", "json", "bundle.json", "report.zip", "sarif", "sqlite"], default=None, help="Output format. Defaults to a readable terminal brief interactively, JSON when piped, and report.zip when --output ends in .zip.")
    scan.add_argument("--online", action="store_true", help="Enable registry and dependency vulnerability checks.")
    scan.add_argument("--known-bad-hashes", help="JSON or line-based SHA-256 feed for known malicious artifacts.")
    scan.add_argument("--threat-feed", help="JSON feed of known malicious or suspicious extension ids.")
    scan.add_argument("--extension-advisories", help="Versioned JSON feed of exact extension vulnerability advisories. Defaults to the bundled snapshot.")
    scan.add_argument("--registry-snapshot", help="Replay registry and dependency intelligence captured in an earlier JSON report.")
    scan.add_argument("--sandbox-observations", help="JSON observations from an external sandbox run. The scanner imports this evidence but does not execute extensions.")
    scan.add_argument("--previous-report", help="Previous ide-scanner JSON report to compare versions, dependencies, scores, and artifacts.")
    scan.add_argument("--out", "--output", dest="output", help="Write report to this file.")
    scan.add_argument("--include-raw-evidence", action="store_true", help="Include raw evidence payloads in dashboard detail files.")
    scan.add_argument("--stream", action="store_true", help="Emit newline-delimited JSON scan events instead of a monolithic JSON report.")
    scan.add_argument("--ui", action="store_true", help="Reserved for local dashboard mode.")

    inventory = subparsers.add_parser("inventory", help="List discovered extension paths without scanning.")
    inventory.add_argument("--all", action="store_true", help="List local VS Code-compatible extension installs.")
    inventory.add_argument("--path", action="append", default=[], help="Extension folder, extensions directory, or VSIX file to inspect.")

    sandbox = subparsers.add_parser("sandbox", help="Create or run a disposable sandbox observation plan.")
    sandbox.add_argument("--path", required=True, help="Extension folder or VSIX file to sandbox.")
    sandbox.add_argument("--out", required=True, help="Write sandbox observations JSON to this file.")
    sandbox.add_argument("--allow-execute", action="store_true", help="Reserved; disabled until OS-level isolation is implemented.")
    sandbox.add_argument("--timeout", type=int, default=15, help="Execution timeout per command in seconds.")

    benchmark = subparsers.add_parser("benchmark", help="Run scanner benchmarks.")
    benchmark_subparsers = benchmark.add_subparsers(dest="benchmark_command")
    benchmark.add_argument("--out", help="Write bundled fixture benchmark JSON result to this file.")

    benchmark_run = benchmark_subparsers.add_parser("run", help="Evaluate a scanner report against a normalized benchmark dataset.")
    benchmark_run.add_argument("--dataset", required=True, help="Normalized benchmark dataset JSON.")
    benchmark_run.add_argument("--report", required=True, help="Scanner report JSON or report.zip to evaluate.")
    benchmark_run.add_argument("--out", "--output", dest="output", help="Write benchmark JSON or benchmark.zip.")
    benchmark_run.add_argument("--format", choices=["json", "benchmark.zip"], default=None, help="Defaults to benchmark.zip when --output ends in .zip.")

    benchmark_normalize = benchmark_subparsers.add_parser("normalize", help="Normalize an external benchmark dataset.")
    benchmark_normalize.add_argument("adapter", choices=["protect-your-secrets"], help="Dataset adapter to use.")
    benchmark_normalize.add_argument("--input", required=True, help="Input dataset file.")
    benchmark_normalize.add_argument("--out", "--output", dest="output", required=True, help="Output normalized JSON file.")
    benchmark_normalize.add_argument("--source-ref", default=None, help="Dataset reference URL or local commit.")

    agent = subparsers.add_parser("agent", help="Run a local scan and upload the report to ide-scanner-web.")
    agent.add_argument("--server", required=True, help="Base URL of the web app, for example http://127.0.0.1:8765.")
    agent.add_argument("--token", help="Bearer token for the web app. Defaults to IDE_SCANNER_AGENT_TOKEN.")
    agent.add_argument("--all", action="store_true", help="Scan local VS Code-compatible extension installs.")
    agent.add_argument("--path", action="append", default=[], help="Extension folder, extensions directory, or VSIX file to scan.")
    agent.add_argument("--online", action="store_true", help="Enable registry and dependency vulnerability checks.")
    agent.add_argument("--previous-report", help="Previous ide-scanner JSON report to compare versions, dependencies, scores, and artifacts.")
    agent.add_argument("--out", help="Also write the upload payload to this local JSON file.")
    agent.add_argument("--timeout", type=int, default=30, help="HTTP upload timeout in seconds.")
    agent.add_argument(
        "--include-source",
        action="store_true",
        help="Include raw source-file previews in the uploaded report. Off by default: source code stays local.",
    )

    args = parser.parse_args(argv)
    if args.command == "scan":
        if args.ui:
            parser.error("scan --ui is not implemented yet. Use `scan --installed --output report.zip` and import the bundle in ide-scanner-web.")
        if args.version and len(args.extension_id) != 1:
            parser.error("scan --version requires exactly one --extension-id")
        report = scan_targets(
            paths=[Path(item) for item in args.path],
            marketplace_scan_ids=args.extension_id,
            marketplace_version=args.version,
            include_fixtures=args.fixtures,
            all_local=args.installed,
            online=args.online or args.profile in {"deep"},
            known_bad_hashes_file=args.known_bad_hashes,
            threat_feed_file=args.threat_feed,
            extension_advisories_file=args.extension_advisories,
            registry_snapshot_file=args.registry_snapshot,
            sandbox_observations_file=args.sandbox_observations,
            previous_report_file=args.previous_report,
        )
        output_format = _scan_output_format(args.output, args.format)
        source = _scan_source(args.installed, args.path, args.extension_id, args.fixtures)
        if args.stream:
            output = ""
            if args.output:
                if output_format != "report.zip":
                    parser.error("scan --stream --output currently writes report.zip bundles only")
                receipt = write_report_bundle(
                    report,
                    args.output,
                    profile=args.profile,
                    source=source,
                    include_raw_evidence=args.include_raw_evidence,
                )
                output = str(receipt["output"])
            _emit_ndjson(iter_report_events(report, profile=args.profile, source=source, output=output))
            return 0
        if output_format == "report.zip":
            if not args.output:
                parser.error("scan --format report.zip requires --output")
            receipt = write_report_bundle(
                report,
                args.output,
                profile=args.profile,
                source=source,
                include_raw_evidence=args.include_raw_evidence,
            )
            _emit(receipt, None)
            return 0
        if output_format == "bundle.json":
            from .report_bundle import build_report_bundle
            _emit(build_report_bundle(report, profile=args.profile, source=source, include_raw_evidence=args.include_raw_evidence), args.output)
            return 0
        if output_format == "terminal":
            if args.output:
                parser.error("scan --format terminal cannot write an output file; use --format report.zip or json.")
            _emit_terminal_brief(report)
            return 0
        if output_format in {"sarif", "sqlite"}:
            parser.error(f"scan --format {output_format} is reserved but not implemented yet")
        _emit(report, args.output)
        return 0
    if args.command == "inventory":
        targets: list[dict[str, str]] = []
        for item in args.path:
            targets.extend(discover_from_path(item))
        if args.all:
            targets.extend(discover_local_installations())
        _emit({"extensions": targets}, None)
        return 0
    if args.command == "sandbox":
        observations = run_sandbox(Path(args.path), allow_execute=args.allow_execute, timeout_seconds=args.timeout)
        _emit(observations, args.out)
        return 0
    if args.command == "benchmark":
        if args.benchmark_command == "run":
            result = run_credential_exposure_benchmark(args.dataset, args.report)
            output_format = args.format or ("benchmark.zip" if args.output and args.output.lower().endswith(".zip") else "json")
            if output_format == "benchmark.zip":
                if not args.output:
                    parser.error("benchmark run --format benchmark.zip requires --output")
                _emit(write_benchmark_bundle(result, args.output), None)
            else:
                _emit(result, args.output)
            return 0
        if args.benchmark_command == "normalize":
            result = write_normalized_dataset(
                args.input,
                args.output,
                source_ref=args.source_ref or "https://github.com/yueyueL/VSCode-Extensions-Security-Analysis/",
            )
            _emit({
                "output": args.output,
                "dataset_id": result["dataset_id"],
                "extension_count": result["extension_count"],
                "credential_extension_count": result["credential_extension_count"],
                "credential_data_points": result["credential_data_points"],
            }, None)
            return 0
        result = _run_benchmark()
        _emit(result, args.out)
        return 0
    if args.command == "agent":
        if not args.all and not args.path:
            parser.error("agent requires --all or at least one --path")
        payload = build_agent_report(
            paths=[Path(item) for item in args.path],
            all_local=args.all,
            online=args.online,
            previous_report_file=args.previous_report,
            include_source=args.include_source,
        )
        if args.out:
            _emit(payload, args.out)
        result = upload_agent_report(
            args.server,
            payload,
            token=args.token or os.environ.get("IDE_SCANNER_AGENT_TOKEN"),
            timeout=args.timeout,
        )
        _emit(_agent_upload_receipt(args.server, result), None)
        return 0
    return 2


def _emit(data: dict[str, Any], out: str | None) -> None:
    payload = json.dumps(data, indent=2, sort_keys=True)
    if out:
        Path(out).write_text(payload + "\n", encoding="utf-8")
        return
    print(payload)


def _emit_ndjson(events) -> None:
    for event in events:
        print(json.dumps(event, sort_keys=True))


def _scan_output_format(output: str | None, explicit_format: str | None) -> str:
    if explicit_format:
        return explicit_format
    if output and output.lower().endswith(".zip"):
        return "report.zip"
    return "terminal" if sys.stdout.isatty() and not output else "json"


def _emit_terminal_brief(report: dict[str, Any]) -> None:
    """Human summary for interactive use; structured output remains the script contract."""
    extensions = [item for item in report.get("extensions", []) if isinstance(item, dict)]
    print("IDE Scanner security brief")
    print(f"{len(extensions)} extension(s) assessed")
    for extension in extensions:
        extension_id = str(extension.get("extension_id") or extension.get("name") or "unknown extension")
        status = str(extension.get("analysis_status") or "incomplete").lower()
        decision = str(extension.get("decision") or "incomplete").upper() if status == "complete" else f"NO DECISION ({status.upper()})"
        risk = int(extension.get("risk_score") or 0)
        malware = int(extension.get("malware_score") or 0)
        coverage = extension.get("analysis_coverage") if isinstance(extension.get("analysis_coverage"), dict) else {}
        percent = int(coverage.get("coverage_percent") or 0)
        print(f"\n{extension_id}  {decision}")
        severity = str(extension.get("severity") or "INFO")
        print(f"  Evidence severity {severity} | Review priority {risk}/100 | Malware evidence {malware}/100 | Coverage {percent}%")
        reason = str(extension.get("decision_reason") or extension.get("verdict_reason") or "No decision explanation recorded.")
        print(f"  {reason}")
        findings = [item for item in extension.get("findings", []) if isinstance(item, dict)]
        for finding in findings[:3]:
            severity = str(finding.get("effective_severity") or finding.get("severity") or "INFO")
            summary = str(finding.get("evidence_summary") or finding.get("rule_id") or "Scanner observation")
            refs = finding.get("file_refs") if isinstance(finding.get("file_refs"), list) else []
            location = f" · {refs[0]}" if refs else ""
            print(f"  [{severity}] {summary}{location}")
        if len(findings) > 3:
            print(f"  + {len(findings) - 3} additional observation(s) in JSON or report bundle")


def _scan_source(installed: bool, paths: list[str], extension_ids: list[str], fixtures: bool) -> str:
    sources: list[str] = []
    if installed:
        sources.append("installed")
    if fixtures:
        sources.append("fixtures")
    if paths:
        if all(Path(item).suffix.lower() == ".vsix" for item in paths):
            sources.append("vsix")
        else:
            sources.append("folder")
    if extension_ids:
        sources.append("marketplace")
    return "+".join(sources) if sources else "unknown"


def _run_benchmark() -> dict[str, Any]:
    truth_path = Path(__file__).resolve().parents[2] / "benchmarks" / "ground-truth.json"
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    threat_feed = truth_path.parent / "threat-feed.json"
    report = scan_targets(
        paths=[truth_path.parent / item["path"] for item in truth["extensions"]],
        threat_feed_file=threat_feed if threat_feed.exists() else None,
    )
    by_id = {extension["extension_id"]: extension for extension in report["extensions"]}
    rows: list[dict[str, Any]] = []
    correct = 0
    false_positive = 0
    false_negative = 0
    for expected in truth["extensions"]:
        extension_id = expected["extension_id"]
        actual = by_id.get(extension_id)
        actual_verdict = actual["verdict"] if actual else "missing"
        ok = actual_verdict == expected["expected_verdict"]
        correct += int(ok)
        if expected["expected_verdict"] in {"clean", "review"} and actual_verdict in {"suspicious", "malicious"}:
            false_positive += 1
        if expected["expected_verdict"] in {"suspicious", "malicious"} and actual_verdict in {"clean", "review", "missing"}:
            false_negative += 1
        rows.append({
            "extension_id": extension_id,
            "expected_verdict": expected["expected_verdict"],
            "actual_verdict": actual_verdict,
            "ok": ok,
            "reason": expected.get("reason", ""),
            "risk_score": actual.get("risk_score") if actual else None,
            "malware_score": actual.get("malware_score") if actual else None,
            "top_findings": [finding["rule_id"] for finding in (actual.get("findings", []) if actual else [])[:5]],
        })
    malicious_expected = [row for row in rows if row["expected_verdict"] in {"suspicious", "malicious"}]
    malicious_detected = [row for row in malicious_expected if row["actual_verdict"] in {"suspicious", "malicious"}]
    return {
        "schema_version": "0.1.0",
        "total": len(rows),
        "correct": correct,
        "accuracy": round(correct / len(rows), 4) if rows else 0,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "malicious_recall": round(len(malicious_detected) / len(malicious_expected), 4) if malicious_expected else 0,
        "rows": rows,
        "scanner_summary": report["summary"],
    }


def _agent_upload_receipt(server: str, result: dict[str, Any]) -> dict[str, Any]:
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    totals = summary.get("summary") if isinstance(summary.get("summary"), dict) else {}
    report_id = str(result.get("id") or "")
    return {
        "id": report_id,
        "status": result.get("status"),
        "source": result.get("source"),
        "report_url": f"{server.rstrip('/')}/api/scans/{report_id}/report" if report_id else "",
        "total_extensions": totals.get("total_extensions", 0),
        "max_risk_score": totals.get("max_risk_score", 0),
        "max_malware_score": totals.get("max_malware_score", 0),
    }


if __name__ == "__main__":
    raise SystemExit(main())
