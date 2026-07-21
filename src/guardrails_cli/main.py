from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .exporters.html import export_html
from .exporters.json_export import export_json
from .exporters.markdown import export_markdown
from .help_manual import TOPICS, manual
from .report_reader import read_report, report_view, validate_report
from .scan_service import run_with_profile, scan_installed
from .scanner_adapter import (
    discover_paths,
    display_report,
    engine_identity,
    get_rules,
    installed_extensions,
    scan_marketplace,
    scan_paths,
    search_extensions,
    write_bundle,
)
from .ui.panels import banner, panel, section
from .ui.prompts import confirm, prompt_choice, prompt_text
from .ui.renderers import render_rules, render_scan_report
from .ui.tables import key_values, table, terminal_width, truncate
from .ui.theme import color, severity_label, severity_style, supports_color


EXPORT_FORMATS = ("terminal", "zip", "html", "md", "json")
IDE_CHOICES = ("vscode", "cursor", "windsurf", "vscodium", "insiders")
PICKER_PAGE_SIZE = 10


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if not arguments:
            if not sys.stdin.isatty():
                build_parser().print_help()
                return 0
            return interactive_application()
        parser = build_parser()
        args = parser.parse_args(arguments)
        if args.command == "scan":
            if arguments == ["scan"] and sys.stdin.isatty() and sys.stdout.isatty():
                return interactive_application()
            return cmd_scan(args)
        if args.command == "report":
            return cmd_report(args)
        if args.command == "rules":
            return cmd_rules(args)
        if args.command == "metrics":
            return cmd_metrics(args)
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "help":
            return cmd_help(args)
        if args.command == "tui":
            return interactive_application()
        if args.command == "version":
            print(f"Guardrails {__version__}")
            return 0
        parser.print_help()
        return 0
    except (EOFError, KeyboardInterrupt):
        print("\n" + color("Cancelled.", "yellow"), file=sys.stderr)
        return 130
    except ValueError as exc:
        print(color(f"Guardrails could not complete the command: {exc}", "red"), file=sys.stderr)
        return 2
    except OSError as exc:
        print(color(f"Guardrails encountered an operational error: {exc}", "red"), file=sys.stderr)
        return 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrails",
        description="Scan extensions installed in VS Code, Cursor, Windsurf, and VSCodium.",
    )
    parser.add_argument("--version", action="version", version=f"Guardrails {__version__}")
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
    scan.add_argument("--fail-on", choices=("block", "review", "never"), default="block", help="Exit 1 when the completed result reaches this decision threshold.")

    report = subparsers.add_parser("report", help="Open, verify, view, or export a saved report.")
    report_subparsers = report.add_subparsers(dest="report_command", required=True)
    view = report_subparsers.add_parser("view", help="Show a saved report in the terminal.")
    view.add_argument("path")
    view.add_argument("--all", action="store_true", help="Print every installation row.")
    view.add_argument("--extension", help="Show one exact extension ID from the saved report.")
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
    help_command = subparsers.add_parser("help", help="Read the Guardrails command and workflow manual.")
    help_command.add_argument("topic", nargs="?", choices=TOPICS)
    subparsers.add_parser("tui", help="Open the interactive Local Scan terminal application.")
    subparsers.add_parser("version", help="Print the Guardrails version.")
    return parser


def interactive_application() -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError("The interactive application requires a terminal. Use `guardrails scan` with explicit flags for automation.")
    try:
        from .tui import launch
    except ImportError as exc:
        raise ValueError("The interactive UI dependency is missing. Reinstall Guardrails to restore Local Scan.") from exc
    result = launch(installed_extensions())
    if result is None:
        return 0
    if result.action == "file":
        return cmd_scan(_scan_namespace(file=result.value))
    if result.action == "report":
        return _view_report(result.value, show_all=False, extension_id=None)
    if result.action == "doctor":
        return cmd_doctor(argparse.Namespace())
    if result.action == "rules":
        return cmd_rules(argparse.Namespace(action="list", query=[]))
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
        report = run_with_profile(args.profile, lambda: scan_marketplace(extension_id, version=version))
        source = "marketplace"
    elif args.file:
        targets = discover_paths(args.file)
        if not targets:
            raise ValueError(f"No extension target was found at {args.file}")
        print(section("Local file target"))
        print(table(["Type", "Path"], [[item.get("type"), item.get("path")] for item in targets], max_widths=[12, 88]))
        print(color("Scanning the selected local artifact without executing extension code…", "brand_cyan"))
        report = run_with_profile(
            args.profile,
            lambda: scan_paths([item["path"] for item in targets], online=args.online or args.profile == "deep"),
        )
        source = "file"
    else:
        selected_rows = _select_installed(args)
        if len(selected_rows) > 1 and not args.yes and sys.stdin.isatty():
            if not confirm(f"Scan {len(selected_rows)} installed extensions", default=True):
                return 130
        report, view = scan_installed(
            selected_rows,
            profile=args.profile,
            online=args.online,
            progress=lambda message: print(color(message, "brand_cyan")),
        )

    if source != "installed":
        view = display_report(report, source=source, profile=args.profile)
    if args.format == "terminal":
        print(render_scan_report(view, show_all=args.show_all))
        if args.output:
            raise ValueError("Terminal output cannot be saved with --output; choose zip, html, md, or json.")
        if sys.stdin.isatty() and confirm("Export this report", default=False):
            labels = (
                "HTML — readable report (recommended)",
                "ZIP — verifiable evidence bundle",
                "JSON — automation and integrations",
                "Markdown — documentation",
                "Skip export",
            )
            selected = prompt_choice("Choose export format", labels)
            if selected == 4:
                return _scan_exit_code(view, args.fail_on)
            fmt = ("html", "zip", "json", "md")[selected]
            output = prompt_text("Output path", default=_default_report_name(view, fmt))
            _export_fresh(report, fmt, output, source=source, profile=args.profile)
            _print_export_result(output, fmt)
    else:
        output = args.output or f"guardrails-report.{args.format}"
        _export_fresh(report, args.format, output, source=source, profile=args.profile)
        _print_export_result(output, args.format)
    return _scan_exit_code(view, args.fail_on)


def _select_installed(args: argparse.Namespace) -> list[dict[str, Any]]:
    rows = installed_extensions()
    if args.ide:
        rows = [row for row in rows if _ide_key(row["client"]) == args.ide]
    if args.extension:
        requested = {value.lower() for value in args.extension}
        rows = [row for row in rows if row["extension_id"].lower() in requested]
    if not rows:
        raise ValueError("No installed extension matches the selected filters.")
    matched = _filter_installed(rows, args.search)
    if not matched:
        raise ValueError(f"No installed extension matches {args.search!r}.")
    if args.all or args.extension:
        _print_scan_scope(matched)
        return matched
    if args.select:
        indices = _parse_selection(args.select, len(matched))
        selected = [matched[index] for index in indices]
        _print_scan_scope(selected)
        return selected
    elif sys.stdin.isatty():
        return _interactive_installed_picker(rows, initial_query=args.search)
    else:
        raise ValueError("Use --all, --extension, or --select when input is not interactive.")


def _marketplace_target(args: argparse.Namespace) -> tuple[str, str | None]:
    if args.marketplace_search:
        results = search_extensions(args.marketplace_search, limit=15)
        if not results:
            raise ValueError("No Marketplace extension matched the search.")
        print(_marketplace_table(results))
        if not sys.stdin.isatty():
            raise ValueError("Marketplace search selection requires an interactive terminal; use --marketplace with an exact ID.")
        index = prompt_choice("Select extension", [str(item.get("extension_id") or "") for item in results], show_choices=False)
        return str(results[index].get("extension_id") or ""), args.version
    value = str(args.marketplace or "")
    if "@" in value:
        extension_id, embedded_version = value.rsplit("@", 1)
        return extension_id, args.version or embedded_version
    return value, args.version


def cmd_report(args: argparse.Namespace) -> int:
    if args.report_command == "view":
        return _view_report(args.path, show_all=args.all, extension_id=args.extension)
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
            _atomic_copy(source, destination)
    elif args.format == "json":
        export_json(data, args.output)
    else:
        view = report_view(data)
        if args.format == "html":
            export_html(view, args.output)
        else:
            export_markdown(view, args.output)
    _print_export_result(args.output, args.format)
    return 0


def _view_report(path: str, *, show_all: bool, extension_id: str | None) -> int:
    data = read_report(path)
    view = report_view(data)
    if extension_id:
        matches = [item for item in view.get("extensions", []) if isinstance(item, dict) and str(item.get("extension_id") or "").lower() == extension_id.lower()]
        if not matches:
            raise ValueError(f"Report does not contain extension {extension_id}.")
        view = {**view, "extensions": matches, "summary": {}}
    print(render_scan_report(view, show_all=show_all))
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


def cmd_help(args: argparse.Namespace) -> int:
    print(manual(args.topic), end="")
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    installed = installed_extensions()
    engine = engine_identity()
    checks = [
        ("Python", "OK", sys.version.split()[0]),
        ("Scanner", "OK" if importlib.util.find_spec("ide_scanner") else "FAIL", f"engine {engine['version']} · build {engine['build'][:12]}"),
        ("Node AST", "OK" if shutil.which("node") else "FAIL", shutil.which("node") or "node not found"),
        ("Semgrep", "OK" if shutil.which("semgrep") else "WARN", shutil.which("semgrep") or "optional; required by deep profile"),
        ("YARA", "OK" if importlib.util.find_spec("yara") else "WARN", "available" if importlib.util.find_spec("yara") else "optional; required by deep profile"),
        ("Installed extensions", "OK" if installed else "WARN", f"{len(installed)} detected"),
        ("Color terminal", "OK" if supports_color() else "WARN", "enabled" if supports_color() else "plain-text mode"),
    ]
    print(banner("Environment doctor"))
    print(table(["Check", "Status", "Detail"], [[name, _status(status), detail] for name, status, detail in checks], max_widths=[24, 10, 76]))
    return 0 if all(status != "FAIL" for _, status, _ in checks) else 4


def _export_fresh(report: dict[str, Any], fmt: str, output: str, *, source: str, profile: str) -> None:
    if fmt == "zip":
        write_bundle(report, output, source=source, profile=profile)
        ok, errors = validate_report(output)
        if not ok:
            raise ValueError("The generated report failed verification: " + "; ".join(errors[:3]))
    elif fmt == "html":
        view = display_report(report, source=source, profile=profile)
        export_html(view, output)
    elif fmt == "md":
        view = display_report(report, source=source, profile=profile)
        export_markdown(view, output)
    elif fmt == "json":
        export_json(report, output)
    else:
        raise ValueError(f"Unsupported export format: {fmt}")


def _filter_installed(rows: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    terms = [term for term in query.lower().split() if term]
    if not terms:
        return rows
    return [
        row for row in rows
        if all(term in " ".join(str(row.get(key) or "") for key in ("display_name", "extension_id", "publisher", "client", "version")).lower() for term in terms)
    ]


def _installation_key(row: dict[str, Any]) -> str:
    return str(row.get("path") or f"{row.get('client')}:{row.get('extension_id')}:{row.get('version')}")


def _interactive_installed_picker(rows: list[dict[str, Any]], *, initial_query: str = "") -> list[dict[str, Any]]:
    query = initial_query.strip()
    page = 0
    selected: dict[str, dict[str, Any]] = {}
    while True:
        matches = _filter_installed(rows, query)
        pages = max(1, (len(matches) + PICKER_PAGE_SIZE - 1) // PICKER_PAGE_SIZE)
        page = min(page, pages - 1)
        start = page * PICKER_PAGE_SIZE
        visible = matches[start:start + PICKER_PAGE_SIZE]
        print(section("Installed extensions"))
        scope = f"{len(rows)} detected · {len(matches)} match{'es' if len(matches) != 1 else ''} · {len(selected)} selected"
        print(color(scope, "gray"))
        if query:
            print(f"Search  {color(query, 'brand')}")
        if visible:
            print(_installed_page(visible, offset=start, selected=set(selected)))
            print(color(f"Page {page + 1}/{pages} · showing {start + 1}-{start + len(visible)} of {len(matches)}", "gray"))
        else:
            print(color("No matches. Press / to search again.", "yellow"))
        print(color("Commands: 1,3-5 toggle · d scan selected · / search · n/p page · a all matches · q cancel", "gray"))
        raw = prompt_text("Choose").strip().lower()
        if raw in {"q", "quit"}:
            raise KeyboardInterrupt
        if raw in {"/", "s", "search"}:
            query = prompt_text("Search name, publisher, or ID").strip()
            page = 0
            continue
        if raw.startswith("/"):
            query = raw[1:].strip()
            page = 0
            continue
        if raw in {"n", "next"}:
            if page + 1 < pages:
                page += 1
            else:
                print(color("Already on the last page.", "yellow"))
            continue
        if raw in {"p", "prev", "previous"}:
            if page:
                page -= 1
            else:
                print(color("Already on the first page.", "yellow"))
            continue
        if raw in {"a", "all"}:
            if not matches:
                continue
            if confirm(f"Scan all {len(matches)} matching installations", default=False):
                _print_scan_scope(matches)
                return matches
            continue
        if raw in {"d", "done", "scan"}:
            if selected:
                result = list(selected.values())
                _print_scan_scope(result)
                return result
            print(color("Select at least one visible row first.", "yellow"))
            continue
        try:
            indices = _parse_selection(raw, len(matches))
        except ValueError:
            print(color("Use visible row numbers or one of the commands shown above.", "yellow"))
            continue
        visible_indices = set(range(start, start + len(visible)))
        if any(index not in visible_indices for index in indices):
            print(color(f"Choose a row shown on this page ({start + 1}-{start + len(visible)}).", "yellow"))
            continue
        for index in indices:
            row = matches[index]
            key = _installation_key(row)
            if key in selected:
                selected.pop(key)
            else:
                selected[key] = row


def _installed_page(rows: list[dict[str, Any]], *, offset: int, selected: set[str]) -> str:
    width = terminal_width()
    lines: list[str] = []
    for position, row in enumerate(rows, start=offset + 1):
        marker = color("●", "brand") if _installation_key(row) in selected else "○"
        name = str(row.get("display_name") or row.get("extension_id") or "Unknown")
        identity = f"{row.get('extension_id', 'unknown')}@{row.get('version', 'unknown')}"
        client = str(row.get("client") or "IDE")
        if width >= 72:
            prefix = f"{position:>3}  {marker}  "
            client_width = 16
            identity_width = max(18, min(42, width - len(prefix) - client_width - 8))
            name_width = max(16, width - len(prefix) - client_width - identity_width - 6)
            lines.append(f"{prefix}{truncate(name, name_width):<{name_width}}  {truncate(identity, identity_width):<{identity_width}}  {truncate(client, client_width)}")
        else:
            lines.append(f"{position:>3}  {marker}  {truncate(name, max(12, width - 9))}")
            lines.append(color(f"        {truncate(identity + ' · ' + client, max(12, width - 8))}", "gray"))
    return "\n".join(lines)


def _print_scan_scope(rows: list[dict[str, Any]]) -> None:
    counts: dict[str, int] = {}
    for row in rows:
        client = str(row.get("client") or "IDE")
        counts[client] = counts.get(client, 0) + 1
    breakdown = " · ".join(f"{client} {count}" for client, count in sorted(counts.items()))
    print(section("Scan scope"))
    print(f"{len(rows)} installation{'s' if len(rows) != 1 else ''} selected" + (f" · {breakdown}" if breakdown else ""))
    if len(rows) <= 5:
        for row in rows:
            print(color(f"  {row.get('extension_id')}@{row.get('version')} · {row.get('client')}", "gray"))


def _scan_exit_code(view: dict[str, Any], fail_on: str) -> int:
    decisions = [_decision(item) for item in view.get("extensions", []) if isinstance(item, dict)]
    if "incomplete" in decisions:
        return 3
    if fail_on == "review" and any(value in {"review", "block"} for value in decisions):
        return 1
    if fail_on == "block" and "block" in decisions:
        return 1
    return 0


def _default_report_name(view: dict[str, Any], fmt: str) -> str:
    scan_id = str((view.get("metadata") or {}).get("scan_id") or view.get("scan_id") or "scan")
    safe = "".join(char if char.isalnum() or char in "-_" else "-" for char in scan_id).strip("-")
    return f"guardrails-{safe or 'scan'}.{fmt}"


def _print_export_result(output: str, fmt: str) -> None:
    path = Path(output).resolve()
    size = path.stat().st_size
    details = [f"Format  {fmt.upper()}", f"Path    {path}", f"Size    {size:,} bytes"]
    if fmt == "zip":
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        ok, _errors = validate_report(path)
        details.extend([f"SHA-256 {digest.hexdigest()}", f"Verify  {'VERIFIED' if ok else 'FAILED'}"])
    print(panel("Report saved", "\n".join(details), subtitle="local file"))


def _atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent, delete=False) as handle:
            temporary = Path(handle.name)
        shutil.copyfile(source, temporary)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


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
        "format": "terminal", "output": None, "show_all": False, "yes": False, "fail_on": "block",
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
