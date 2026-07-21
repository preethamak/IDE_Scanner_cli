from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .exporters.html import export_html
from .exporters.json_export import export_json
from .exporters.markdown import export_markdown
from .report_reader import read_report, report_view, validate_report
from .scanner_adapter import (
    discover_paths,
    display_report,
    get_rules,
    installed_extensions,
    scan_marketplace,
    scan_paths,
    search_extensions,
    write_bundle,
)
from .snapshot import snapshot_installations
from .ui.panels import banner, panel, section
from .ui.prompts import confirm, prompt_choice, prompt_indices, prompt_text
from .ui.renderers import render_rules, render_scan_report
from .ui.tables import key_values, table
from .ui.theme import color, severity_label, severity_style, supports_color


EXPORT_FORMATS = ("terminal", "zip", "html", "md", "json")
IDE_CHOICES = ("vscode", "cursor", "windsurf", "vscodium", "insiders")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if not arguments:
            if not sys.stdin.isatty():
                build_parser().print_help()
                return 0
            return interactive_home()
        parser = build_parser()
        args = parser.parse_args(arguments)
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "report":
            return cmd_report(args)
        if args.command == "rules":
            return cmd_rules(args)
        if args.command == "metrics":
            return cmd_metrics(args)
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "version":
            print(f"Guardrails {__version__}")
            return 0
        parser.print_help()
        return 0
    except (EOFError, KeyboardInterrupt):
        print("\n" + color("Cancelled.", "yellow"), file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        print(color(f"Guardrails could not complete the command: {exc}", "red"), file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrails",
        description="Scan extensions installed in VS Code, Cursor, Windsurf, and VSCodium.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan locally installed extensions (default source).")
    source = scan.add_mutually_exclusive_group()
    source.add_argument("--file", metavar="PATH", help="Scan a VSIX, ZIP, or unpacked extension folder.")
    source.add_argument("--marketplace", metavar="ID[@VERSION]", help="Scan one exact Marketplace extension.")
    source.add_argument("--marketplace-search", metavar="QUERY", help="Search Marketplace, select, and scan an extension.")
    scan.add_argument("--all", action="store_true", help="Scan every installed extension matching the filters.")
    scan.add_argument("--ide", choices=IDE_CHOICES, help="Limit installed extensions to one IDE client.")
    scan.add_argument("--search", "--filter", dest="search", default="", help="Search installed extension names, publishers, and IDs.")
    scan.add_argument("--extension", action="append", default=[], help="Scan this installed extension ID; repeat for more than one.")
    scan.add_argument("--select", help="Select displayed rows, for example 1,3-5 or all.")
    scan.add_argument("--version", help="Exact Marketplace version; may also be supplied as ID@VERSION.")
    scan.add_argument(
        "--profile",
        choices=("offline", "standard", "deep"),
        default="standard",
        help="Analysis boundary. Deep matches the website Deep Scan when its required providers are available.",
    )
    scan.add_argument("--online", action="store_true", help="Enable registry and dependency checks for local/file scans.")
    scan.add_argument("--format", choices=EXPORT_FORMATS, default="terminal", help="Output or saved-report format.")
    scan.add_argument("--output", "--out", dest="output", help="Write the selected report format to this path.")
    scan.add_argument("--show-all", action="store_true", help="Print every installation in a multi-extension terminal report.")
    scan.add_argument("--yes", action="store_true", help="Skip confirmation before scanning all matching installations.")

    report = subparsers.add_parser("report", help="Open, verify, view, or export a saved report.")
    report_subparsers = report.add_subparsers(dest="report_command", required=True)
    view = report_subparsers.add_parser("view", help="Show a saved report in the terminal.")
    view.add_argument("path")
    view.add_argument("--all", action="store_true", help="Print every installation row.")
    verify = report_subparsers.add_parser("verify", aliases=["validate"], help="Verify report structure and identities.")
    verify.add_argument("path")
    export = report_subparsers.add_parser("export", help="Export without recalculating scanner evidence.")
    export.add_argument("path")
    export.add_argument("--format", choices=("zip", "html", "md", "json"), required=True)
    export.add_argument("--output", "--out", dest="output", required=True)

    rules = subparsers.add_parser("rules", help="Browse the scanner rule catalog.")
    rules.add_argument("action", nargs="?", choices=("list", "search", "show"), default="list")
    rules.add_argument("query", nargs="*")

    metrics = subparsers.add_parser("metrics", help="Explain decisions, scores, evidence, and coverage.")
    metrics.add_argument("topic", nargs="?", choices=("decisions", "scores", "evidence", "coverage", "all"), default="all")
    subparsers.add_parser("doctor", help="Check local scan dependencies and detected IDE clients.")
    subparsers.add_parser("version", help="Print the Guardrails version.")
    return parser


def interactive_home() -> int:
    rows = installed_extensions()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["client"]] = counts.get(row["client"], 0) + 1
    detected = "\n".join(f"{client:<18} {count:>4} installed" for client, count in sorted(counts.items())) or "No supported IDE extensions detected."
    print(banner("Local IDE extension scanner"))
    print(panel("Installed extensions", detected, subtitle=f"{len(rows)} detected"))
    choices = [
        "Scan installed extensions",
        "Search installed extensions",
        "Scan a VSIX, ZIP, or folder",
        "Scan a Marketplace extension",
        "View or verify a report",
        "Detection rules",
        "Environment doctor",
        "Help",
    ]
    print(table(["#", "Action"], [[index, label] for index, label in enumerate(choices, start=1)], max_widths=[4, 48]))
    selected = prompt_choice("Select action", choices)
    if selected == 0:
        return cmd_scan(_scan_namespace())
    if selected == 1:
        return cmd_scan(_scan_namespace(search=prompt_text("Search installed extensions")))
    if selected == 2:
        return cmd_scan(_scan_namespace(file=prompt_text("VSIX, ZIP, or extension folder")))
    if selected == 3:
        return cmd_scan(_scan_namespace(marketplace_search=prompt_text("Marketplace search")))
    if selected == 4:
        path = prompt_text("Report path")
        return _view_report(path, show_all=False)
    if selected == 5:
        return cmd_rules(argparse.Namespace(action="list", query=[]))
    if selected == 6:
        return cmd_doctor(argparse.Namespace())
    build_parser().print_help()
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    if args.profile == "offline" and args.online:
        raise ValueError("--profile offline cannot be combined with --online.")
    if args.profile == "offline" and (args.marketplace or args.marketplace_search):
        raise ValueError("Marketplace acquisition requires a network connection and cannot use the offline profile.")
    source = "installed"
    selected_rows: list[dict[str, Any]] = []
    if args.marketplace or args.marketplace_search:
        extension_id, version = _marketplace_target(args)
        print(color(f"Acquiring exact Marketplace artifact {extension_id}{f'@{version}' if version else ''}…", "brand_cyan"))
        report = _run_with_profile(args.profile, lambda: scan_marketplace(extension_id, version=version))
        source = "marketplace"
    elif args.file:
        targets = discover_paths(args.file)
        if not targets:
            raise ValueError(f"No extension target was found at {args.file}")
        print(section("Local file target"))
        print(table(["Type", "Path"], [[item.get("type"), item.get("path")] for item in targets], max_widths=[12, 88]))
        print(color("Scanning the selected local artifact without executing extension code…", "brand_cyan"))
        report = _run_with_profile(
            args.profile,
            lambda: scan_paths([item["path"] for item in targets], online=args.online or args.profile == "deep"),
        )
        source = "file"
    else:
        selected_rows = _select_installed(args)
        if len(selected_rows) > 1 and not args.yes and sys.stdin.isatty():
            if not confirm(f"Scan {len(selected_rows)} installed extensions", default=True):
                return 130
        print(color(f"Creating a stable local snapshot of {len(selected_rows)} installed extension(s)…", "brand_cyan"))
        with snapshot_installations(selected_rows) as snapshot_rows:
            print(color("Scanning the snapshots without executing extension code…", "brand_cyan"))
            report = _run_with_profile(
                args.profile,
                lambda: scan_paths([row["path"] for row in snapshot_rows], online=args.online or args.profile == "deep"),
            )
            _attach_installation_context(report, snapshot_rows)

    view = display_report(report, source=source, profile=args.profile)
    if args.format == "terminal":
        print(render_scan_report(view, show_all=args.show_all))
        if args.output:
            raise ValueError("Terminal output cannot be saved with --output; choose zip, html, md, or json.")
        if sys.stdin.isatty() and confirm("Export this report", default=False):
            fmt = ("zip", "html", "md", "json")[prompt_choice("Format", ("zip", "html", "md", "json"))]
            output = prompt_text("Output path", default=f"guardrails-report.{fmt}")
            _export_fresh(report, view, fmt, output, source=source, profile=args.profile)
            print(color(f"Saved {output}", "green"))
    else:
        output = args.output or f"guardrails-report.{args.format}"
        _export_fresh(report, view, args.format, output, source=source, profile=args.profile)
        print(color(f"Saved {output}", "green"))
    return 3 if any(_decision(item) == "incomplete" for item in view.get("extensions", [])) else 0


def _select_installed(args: argparse.Namespace) -> list[dict[str, Any]]:
    rows = installed_extensions()
    if args.ide:
        rows = [row for row in rows if _ide_key(row["client"]) == args.ide]
    if args.search:
        needle = args.search.lower()
        rows = [row for row in rows if needle in json.dumps(row, sort_keys=True).lower()]
    if args.extension:
        requested = {value.lower() for value in args.extension}
        rows = [row for row in rows if row["extension_id"].lower() in requested]
    if not rows:
        raise ValueError("No installed extension matches the selected filters.")
    print(section("Installed extensions"))
    print(_installed_table(rows))
    if args.all or args.extension:
        return rows
    if args.select:
        indices = _parse_selection(args.select, len(rows))
    elif sys.stdin.isatty():
        indices = prompt_indices("Select extensions (1,3-5 or all)", [row["extension_id"] for row in rows])
    else:
        raise ValueError("Use --all, --extension, or --select when input is not interactive.")
    return [rows[index] for index in indices]


def _marketplace_target(args: argparse.Namespace) -> tuple[str, str | None]:
    if args.marketplace_search:
        results = search_extensions(args.marketplace_search, limit=15)
        if not results:
            raise ValueError("No Marketplace extension matched the search.")
        print(_marketplace_table(results))
        if not sys.stdin.isatty():
            raise ValueError("Marketplace search selection requires an interactive terminal; use --marketplace with an exact ID.")
        index = prompt_choice("Select extension", [str(item.get("extension_id") or "") for item in results])
        return str(results[index].get("extension_id") or ""), args.version
    value = str(args.marketplace or "")
    if "@" in value:
        extension_id, embedded_version = value.rsplit("@", 1)
        return extension_id, args.version or embedded_version
    return value, args.version


def cmd_report(args: argparse.Namespace) -> int:
    if args.report_command == "view":
        return _view_report(args.path, show_all=args.all)
    if args.report_command in {"verify", "validate"}:
        ok, errors = validate_report(args.path)
        print(panel("Report verification", f"{args.path}\n\n{'VERIFIED' if ok else 'FAILED'}", subtitle="Guardrails"))
        for error in errors[:20]:
            print(color(f"- {error}", "red"))
        if len(errors) > 20:
            print(color(f"- {len(errors) - 20} additional verification error(s) omitted", "red"))
        return 0 if ok else 1
    data = read_report(args.path)
    if args.format == "zip":
        if Path(args.path).suffix.lower() != ".zip":
            raise ValueError("Only an existing canonical ZIP can be exported as ZIP without rebuilding evidence.")
        source = Path(args.path).resolve()
        destination = Path(args.output).resolve()
        if source != destination:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    elif args.format == "json":
        export_json(data, args.output)
    else:
        view = report_view(data)
        if args.format == "html":
            export_html(view, args.output)
        else:
            export_markdown(view, args.output)
    print(color(f"Saved {args.output}", "green"))
    return 0


def _view_report(path: str, *, show_all: bool) -> int:
    data = read_report(path)
    print(render_scan_report(report_view(data), show_all=show_all))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    catalog = get_rules()
    rules = list(catalog.get("rules") or [])
    query = " ".join(args.query).strip()
    if args.action == "search":
        if not query:
            query = prompt_text("Rule search")
        rules = [rule for rule in rules if query.lower() in json.dumps(rule).lower()]
    elif args.action == "show":
        if not query:
            query = prompt_text("Rule ID")
        match = next((rule for rule in rules if rule.get("rule_id") == query), None)
        if not match:
            raise ValueError(f"Rule not found: {query}")
        print(panel(str(match.get("rule_id")), key_values([
            ("Title", match.get("title", "")),
            ("Category", match.get("category", "")),
            ("Severity", color(severity_label(str(match.get("default_severity") or "")), severity_style(str(match.get("default_severity") or "")))),
            ("Evidence", match.get("evidence_class", "")),
            ("Description", match.get("description", "")),
            ("Recommendation", match.get("recommendation", "")),
            ("False positives", match.get("false_positive_notes", "")),
        ]), subtitle="detection rule"))
        return 0
    print(banner("Detection rules"))
    print(panel("Rule catalog", f"Ruleset {catalog.get('ruleset_version', 'unknown')} · {len(rules)} rule(s)", subtitle="local scanner"))
    print(render_rules(rules))
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    topics = {
        "decisions": [
            ("ALLOW", "Required analysis completed and no decision-level evidence requires review."),
            ("REVIEW", "The extension has capabilities or evidence that need human context."),
            ("BLOCK", "The report contains authoritative or high-specificity evidence supporting a block."),
            ("INCOMPLETE", "Acquisition or required analysis did not complete; no allow conclusion is available."),
        ],
        "scores": [
            ("Risk", "Review priority based on security-relevant behavior and access."),
            ("Malware evidence", "Reserved for authoritative threat sources or high-specificity observed proof."),
        ],
        "evidence": [
            ("confirmed", "Known-bad artifact or equivalent authoritative source."),
            ("correlated", "Multiple related signals forming a concrete behavior chain."),
            ("capability", "Powerful access or behavior that requires product context."),
            ("weak", "A standalone observation that cannot establish intent."),
        ],
        "coverage": [
            ("Complete", "Every provider required by the selected profile completed."),
            ("Incomplete", "At least one required provider or artifact step failed."),
            ("Unavailable", "An optional provider was not installed or not requested."),
        ],
    }
    rows: list[tuple[str, str]] = []
    if args.topic == "all":
        for values in topics.values():
            rows.extend(values)
    else:
        rows = topics[args.topic]
    print(banner("How results are reported"))
    print(table(["Term", "Meaning"], rows, max_widths=[22, 96]))
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    installed = installed_extensions()
    checks = [
        ("Python", "OK", sys.version.split()[0]),
        ("Scanner", "OK" if importlib.util.find_spec("ide_scanner") else "FAIL", "local analysis engine"),
        ("Node AST", "OK" if shutil.which("node") else "FAIL", shutil.which("node") or "node not found"),
        ("Semgrep", "OK" if shutil.which("semgrep") else "WARN", shutil.which("semgrep") or "optional; required by deep profile"),
        ("YARA", "OK" if importlib.util.find_spec("yara") else "WARN", "available" if importlib.util.find_spec("yara") else "optional; required by deep profile"),
        ("Installed extensions", "OK" if installed else "WARN", f"{len(installed)} detected"),
        ("Color terminal", "OK" if supports_color() else "WARN", "enabled" if supports_color() else "plain-text mode"),
    ]
    print(banner("Environment doctor"))
    print(table(["Check", "Status", "Detail"], [[name, _status(status), detail] for name, status, detail in checks], max_widths=[24, 10, 76]))
    return 0 if all(status != "FAIL" for _, status, _ in checks) else 1


def _export_fresh(report: dict[str, Any], view: dict[str, Any], fmt: str, output: str, *, source: str, profile: str) -> None:
    if fmt == "zip":
        duplicates = _duplicate_installation_identities(view)
        if duplicates:
            examples = ", ".join(f"{extension_id}@{version}" for extension_id, version in duplicates[:3])
            raise ValueError(
                "A canonical ZIP cannot represent duplicate installations of the same extension version "
                f"without merging detail records ({examples}). Export JSON, HTML, or Markdown instead."
            )
        write_bundle(report, output, source=source, profile=profile)
        ok, errors = validate_report(output)
        if not ok:
            raise ValueError("The generated report failed verification: " + "; ".join(errors[:3]))
    elif fmt == "html":
        export_html(view, output)
    elif fmt == "md":
        export_markdown(view, output)
    elif fmt == "json":
        export_json(report, output)
    else:
        raise ValueError(f"Unsupported export format: {fmt}")


def _duplicate_installation_identities(view: dict[str, Any]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    duplicates: list[tuple[str, str]] = []
    for item in view.get("extensions", []):
        if not isinstance(item, dict):
            continue
        identity = (str(item.get("extension_id") or "unknown"), str(item.get("version") or "unknown"))
        if identity in seen and identity not in duplicates:
            duplicates.append(identity)
        seen.add(identity)
    return duplicates


def _attach_installation_context(report: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    by_path = {str(Path(row["path"]).resolve()): row for row in rows}
    for extension in report.get("extensions", []):
        if not isinstance(extension, dict):
            continue
        install_path = str(extension.get("install_path") or "")
        try:
            context = by_path.get(str(Path(install_path).resolve()))
        except OSError:
            context = None
        if context:
            extension["client"] = context["client"]
            extension["installation_path"] = context.get("original_path") or context["path"]


def _run_with_profile(profile: str, operation):
    previous = os.environ.get("IDE_SCANNER_REQUIRE_PROVIDERS")
    if profile == "deep":
        existing = {item.strip() for item in (previous or "").split(",") if item.strip()}
        existing.update({"semgrep", "yara", "dependency_intelligence"})
        os.environ["IDE_SCANNER_REQUIRE_PROVIDERS"] = ",".join(sorted(existing))
    try:
        return operation()
    finally:
        if previous is None:
            os.environ.pop("IDE_SCANNER_REQUIRE_PROVIDERS", None)
        else:
            os.environ["IDE_SCANNER_REQUIRE_PROVIDERS"] = previous


def _installed_table(rows: list[dict[str, Any]]) -> str:
    return table(
        ["#", "IDE", "Extension", "Version", "Publisher", "ID"],
        [[index, item["client"], item["display_name"], item["version"], item["publisher"], item["extension_id"]] for index, item in enumerate(rows, start=1)],
        max_widths=[4, 16, 30, 14, 18, 38],
    )


def _marketplace_table(results: list[dict[str, Any]]) -> str:
    return table(
        ["#", "Extension", "Publisher", "Version", "Installs", "ID"],
        [[index, item.get("display_name") or item.get("extension_id"), item.get("publisher", ""), item.get("version", ""), _compact_int(item.get("install_count", 0)), item.get("extension_id", "")] for index, item in enumerate(results, start=1)],
        max_widths=[4, 30, 18, 14, 10, 38],
    )


def _parse_selection(value: str, count: int) -> list[int]:
    if value.lower() in {"all", "a"}:
        return list(range(count))
    selected: set[int] = set()
    try:
        for token in value.split(","):
            token = token.strip()
            if "-" in token:
                start, end = (int(part) for part in token.split("-", 1))
                selected.update(range(start - 1, end))
            else:
                selected.add(int(token) - 1)
    except ValueError as exc:
        raise ValueError("Invalid --select value; use 1,3-5 or all.") from exc
    if not selected or min(selected) < 0 or max(selected) >= count:
        raise ValueError(f"Selection must refer to rows 1-{count}.")
    return sorted(selected)


def _scan_namespace(**overrides: Any) -> argparse.Namespace:
    defaults = {
        "file": None, "marketplace": None, "marketplace_search": None,
        "all": False, "ide": None, "search": "", "extension": [], "select": None,
        "version": None, "profile": "standard", "online": False,
        "format": "terminal", "output": None, "show_all": False, "yes": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _ide_key(client: str) -> str:
    value = client.lower()
    if "cursor" in value:
        return "cursor"
    if "windsurf" in value:
        return "windsurf"
    if "vscodium" in value:
        return "vscodium"
    if "insiders" in value:
        return "insiders"
    return "vscode"


def _decision(extension: dict[str, Any]) -> str:
    value = str(extension.get("decision") or "").lower()
    if value in {"allow", "review", "block", "incomplete"}:
        return value
    return {"clean": "allow", "review": "review", "suspicious": "review", "malicious": "block"}.get(str(extension.get("verdict") or "").lower(), "incomplete")


def _compact_int(value: object) -> str:
    number = int(value or 0)
    if number >= 1_000_000:
        return f"{number / 1_000_000:.1f}M"
    if number >= 1_000:
        return f"{number / 1_000:.1f}K"
    return str(number)


def _status(value: str) -> str:
    return color(value, "green" if value == "OK" else "yellow" if value == "WARN" else "red")


if __name__ == "__main__":
    raise SystemExit(main())
