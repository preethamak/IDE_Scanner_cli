from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.markdown import Markdown as RichMarkdown
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.events import Resize
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Footer,
    Input,
    Label,
    Select,
    SelectionList,
    Static,
)

from .exporters.html import export_html
from .exporters.json_export import export_json
from .exporters.markdown import export_markdown, to_markdown
from .help_manual import interactive_manual
from .report_reader import validate_report
from .scan_service import scan_installed
from .scanner_adapter import write_bundle
from .ui.panels import compact_logo_lines


@dataclass(frozen=True)
class TuiResult:
    action: str
    value: str = ""


class HelpScreen(ModalScreen[None]):
    BINDINGS = [("escape", "dismiss", "Close")]

    def compose(self) -> ComposeResult:
        with Container(classes="dialog help-dialog"):
            yield Label("Guardrails manual", classes="dialog-title")
            with VerticalScroll(id="help-document"):
                yield Static(RichMarkdown(interactive_manual()), classes="markdown-content")
            yield Button("Close", id="close-help", variant="primary")

    def action_dismiss(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#close-help")
    def close_help(self) -> None:
        self.dismiss(None)


class PathScreen(ModalScreen[str | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, title: str, placeholder: str) -> None:
        super().__init__()
        self.dialog_title = title
        self.placeholder = placeholder

    def compose(self) -> ComposeResult:
        with Container(classes="dialog path-dialog"):
            yield Label(self.dialog_title, classes="dialog-title")
            yield Input(placeholder=self.placeholder, id="path-value")
            with Horizontal(classes="dialog-actions"):
                yield Button("Cancel", id="cancel-path")
                yield Button("Continue", id="submit-path", variant="primary")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted)
    def submit_input(self, event: Input.Submitted) -> None:
        self._submit(event.value)

    @on(Button.Pressed)
    def handle_button(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-path":
            self.dismiss(None)
        elif event.button.id == "submit-path":
            self._submit(self.query_one(Input).value)

    def _submit(self, value: str) -> None:
        cleaned = value.strip()
        if not cleaned:
            self.notify("Enter a path to continue.", severity="warning")
            return
        self.dismiss(cleaned)


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Container(classes="dialog confirm-dialog"):
            yield Label("Confirm scan", classes="dialog-title")
            yield Static(self.message)
            with Horizontal(classes="dialog-actions"):
                yield Button("Cancel", id="cancel-confirm")
                yield Button("Scan", id="accept-confirm", variant="primary")

    def action_cancel(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed)
    def handle_button(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "accept-confirm")


class GuardrailsApp(App[TuiResult | None]):
    TITLE = "Guardrails Local Scan"
    SUB_TITLE = "Installed extension security"

    CSS = """
    $surface: #14202b;
    $panel: #192a36;
    $ink: #eef3f6;
    $muted: #8fa0ad;
    $brand: #c9ff45;
    $pink: #f13b71;
    $cyan: #17aefd;

    Screen {
        background: #0c1218;
        color: $ink;
    }

    #hero {
        height: 7;
        padding: 0 2;
        background: $surface;
        border-bottom: solid $brand;
    }

    #brand-mark {
        width: 13;
        height: 6;
        padding-top: 1;
    }

    #brand-copy {
        width: 1fr;
        height: 6;
        padding: 1 1 0 1;
    }

    #wordmark {
        color: $ink;
        text-style: bold;
        height: 2;
    }

    #product-name { color: $brand; height: 1; }
    #inventory-summary { color: $muted; height: 1; }

    #filters {
        height: 5;
        padding: 1 2;
        background: #101a22;
    }

    #search { width: 1fr; margin-right: 1; }
    #ide-filter { width: 22; margin-right: 1; }
    #profile-filter { width: 18; }

    Input, Select {
        border: tall #385060;
        background: $surface;
    }

    Input:focus, Select:focus { border: tall $brand; }

    #workspace {
        height: 1fr;
        padding: 0 2 1 2;
    }

    #inventory-pane {
        width: 2fr;
        height: 1fr;
        margin-right: 1;
    }

    #detail-pane {
        width: 1fr;
        height: 1fr;
        padding: 1 2;
        background: $surface;
        border: round #385060;
    }

    #selection-status { height: 2; color: $muted; }

    #extensions {
        height: 1fr;
        background: $surface;
        border: round #385060;
        padding: 0 1;
    }

    #extensions:focus { border: round $brand; }

    #primary-actions, #report-actions {
        height: 3;
        margin-top: 1;
    }

    Button { margin-right: 1; min-width: 12; }
    Button.-primary { background: $brand; color: #14202b; }

    #secondary-actions {
        height: 3;
        padding: 0 2;
        background: #101a22;
    }

    #progress-view {
        display: none;
        height: 1fr;
        align: center middle;
    }

    #progress-card {
        width: 64;
        height: 12;
        padding: 1 3;
        background: $surface;
        border: round $brand;
        content-align: center middle;
    }

    #progress-title { text-style: bold; color: $brand; text-align: center; }
    #progress-pulse { color: $pink; text-align: center; height: 2; }
    #progress-message { color: $muted; text-align: center; }

    #results-view {
        display: none;
        height: 1fr;
        padding: 1 2;
    }

    #outcome-summary {
        height: 4;
        padding: 1 2;
        margin-bottom: 1;
        background: $surface;
        border-left: thick $brand;
    }

    #report-scroll {
        height: 1fr;
        padding: 1 2;
        background: $surface;
        border: round #385060;
    }

    .markdown-content { height: auto; }

    Footer { background: $surface; }

    HelpScreen, PathScreen, ConfirmScreen {
        align: center middle;
        background: #000000 65%;
    }

    .dialog {
        padding: 1 2;
        background: $surface;
        border: round $brand;
    }

    .help-dialog { width: 86%; height: 86%; }
    .path-dialog { width: 68; height: 12; }
    .confirm-dialog { width: 64; height: 12; }
    .dialog-title { height: 2; color: $brand; text-style: bold; }
    .dialog-actions { height: 3; margin-top: 1; align-horizontal: right; }
    #help-document { height: 1fr; }

    .narrow #hero { height: 6; padding: 0 1; }
    .narrow #brand-mark { width: 12; height: 5; padding-top: 0; }
    .narrow #brand-copy { height: 5; padding-top: 0; }
    .narrow #filters { height: 5; padding: 1; }
    .narrow #search { width: 100%; height: 3; margin: 0; }
    .narrow #ide-filter, .narrow #profile-filter { display: none; }
    .narrow #workspace { padding: 0 1 1 1; }
    .narrow #inventory-pane { width: 1fr; margin: 0; }
    .narrow #detail-pane { display: none; }
    .narrow #secondary-actions { padding: 0 1; }
    .narrow Button { min-width: 8; }
    """

    BINDINGS = [
        Binding("ctrl+s", "scan_selected", "Scan selected", priority=True),
        Binding("ctrl+a", "scan_matches", "Scan matches", priority=True),
        Binding("/", "focus_search", "Search", priority=True),
        Binding("?", "help", "Help", priority=True),
        Binding("escape", "back", "Back"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        super().__init__()
        self.rows = rows
        self.by_key = {_row_key(row): row for row in rows}
        self.visible_rows = list(rows)
        self.selected_keys: set[str] = set()
        self.raw_report: dict[str, Any] | None = None
        self.view_report: dict[str, Any] | None = None
        self.report_profile = "standard"

    def compose(self) -> ComposeResult:
        logo = compact_logo_lines()
        mark = Text.from_ansi("\n".join(logo)) if logo else Text("GR", style="bold #c9ff45")
        with Horizontal(id="hero"):
            yield Static(mark, id="brand-mark")
            with Vertical(id="brand-copy"):
                yield Static("G U A R D R A I L S", id="wordmark")
                yield Static("LOCAL SCAN", id="product-name")
                yield Static("Discovering installed extensions…", id="inventory-summary")
        with Horizontal(id="filters"):
            yield Input(placeholder="Search name, publisher, or extension ID", id="search")
            yield Select(self._ide_options(), value="", allow_blank=False, id="ide-filter")
            yield Select(
                (("Standard", "standard"), ("Offline", "offline"), ("Deep", "deep")),
                value="standard",
                allow_blank=False,
                id="profile-filter",
            )
        with Horizontal(id="workspace"):
            with Vertical(id="inventory-pane"):
                yield Static("", id="selection-status")
                yield SelectionList[str](id="extensions")
                with Horizontal(id="primary-actions"):
                    yield Button("Scan selected", id="scan-selected", variant="primary")
                    yield Button("Scan matches", id="scan-matches")
            yield Static("Select an extension to inspect its installation details.", id="detail-pane")
        with Container(id="progress-view"):
            with Vertical(id="progress-card"):
                yield Static("Scanning locally", id="progress-title")
                yield Static("●  ●  ●", id="progress-pulse")
                yield Static("Preparing scan…", id="progress-message")
        with Vertical(id="results-view"):
            yield Static("", id="outcome-summary")
            with VerticalScroll(id="report-scroll"):
                yield Static("", id="report-document", classes="markdown-content")
            with Horizontal(id="report-actions"):
                yield Button("Back", id="back-to-picker")
                yield Button("HTML", id="export-html", variant="primary")
                yield Button("ZIP", id="export-zip")
                yield Button("JSON", id="export-json")
                yield Button("Markdown", id="export-md")
        with Horizontal(id="secondary-actions"):
            yield Button("Scan file", id="scan-file")
            yield Button("Open report", id="open-report")
            yield Button("Doctor", id="doctor")
            yield Button("Rules", id="rules")
            yield Button("Help", id="help")
        yield Footer()

    def on_mount(self) -> None:
        self._set_responsive_state(self.size.width)
        self.query_one("#inventory-summary", Static).update(self._inventory_summary())
        self._refresh_inventory()
        self.query_one("#extensions", SelectionList).focus()

    def on_resize(self, event: Resize) -> None:
        self._set_responsive_state(event.size.width)

    def _set_responsive_state(self, width: int) -> None:
        narrow = width < 90
        self.screen.set_class(narrow, "narrow")
        search = self.query_one_optional("#search", Input)
        if search is not None:
            search.placeholder = (
                "Search installed extensions · All IDEs · Standard"
                if narrow
                else "Search name, publisher, or extension ID"
            )

    def _ide_options(self) -> list[tuple[str, str]]:
        clients = sorted({str(row.get("client") or "IDE") for row in self.rows})
        return [("All IDEs", ""), *((client, client) for client in clients)]

    def _inventory_summary(self) -> str:
        counts: dict[str, int] = {}
        for row in self.rows:
            client = str(row.get("client") or "IDE")
            counts[client] = counts.get(client, 0) + 1
        detail = "  ·  ".join(f"{client} {count}" for client, count in sorted(counts.items()))
        return f"{len(self.rows)} installed" + (f"  ·  {detail}" if detail else "")

    def _refresh_inventory(self) -> None:
        listing = self.query_one("#extensions", SelectionList)
        self.selected_keys.update(str(value) for value in listing.selected)
        query = self.query_one("#search", Input).value.lower().strip()
        ide_value = self.query_one("#ide-filter", Select).value
        terms = query.split()
        self.visible_rows = [
            row
            for row in self.rows
            if (not ide_value or row.get("client") == ide_value)
            and all(term in _search_text(row) for term in terms)
        ]
        listing.set_options(
            [(_row_prompt(row), _row_key(row), _row_key(row) in self.selected_keys) for row in self.visible_rows]
        )
        self._update_selection_status()
        if self.visible_rows:
            self._show_detail(self.visible_rows[0])
        else:
            self.query_one("#detail-pane", Static).update("No installed extension matches these filters.")

    def _update_selection_status(self) -> None:
        self.query_one("#selection-status", Static).update(
            f"{len(self.visible_rows)} shown  ·  {len(self.selected_keys)} selected  ·  Space toggles selection"
        )

    @on(Input.Changed, "#search")
    def search_changed(self) -> None:
        self._refresh_inventory()

    @on(Select.Changed, "#ide-filter")
    def ide_changed(self) -> None:
        self._refresh_inventory()

    @on(SelectionList.SelectedChanged, "#extensions")
    def selected_changed(self, event: SelectionList.SelectedChanged) -> None:
        visible_keys = {_row_key(row) for row in self.visible_rows}
        self.selected_keys.difference_update(visible_keys)
        self.selected_keys.update(str(value) for value in event.selection_list.selected)
        self._update_selection_status()

    @on(SelectionList.SelectionHighlighted, "#extensions")
    def highlighted(self, event: SelectionList.SelectionHighlighted) -> None:
        row = self.by_key.get(str(event.selection.value))
        if row:
            self._show_detail(row)

    def _show_detail(self, row: dict[str, Any]) -> None:
        self.query_one("#detail-pane", Static).update(
            "[b]Installation details[/b]\n\n"
            f"[b]{_display_name(row)}[/b]\n"
            f"{row.get('extension_id')}@{row.get('version')}\n\n"
            f"IDE       {row.get('client')}\n"
            f"Publisher {row.get('publisher') or 'Unknown'}\n\n"
            "The extension will be copied to a private temporary snapshot. Its code is never executed."
        )

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_back(self) -> None:
        if self.query_one("#results-view").display:
            self._show_view("picker")
            return
        search = self.query_one("#search", Input)
        if search.value:
            search.value = ""
        self.query_one("#extensions", SelectionList).focus()

    def action_quit(self) -> None:
        self.exit(None)

    def action_scan_selected(self) -> None:
        rows = [row for row in self.rows if _row_key(row) in self.selected_keys]
        if not rows:
            self.notify("Select at least one extension with Space.", severity="warning")
            return
        self._begin_scan(rows)

    def action_scan_matches(self) -> None:
        if not self.visible_rows:
            self.notify("No extensions match the current filters.", severity="warning")
            return
        count = len(self.visible_rows)
        self.push_screen(
            ConfirmScreen(f"Scan all {count} extensions matching the current search and IDE filter?"),
            lambda accepted: self._begin_scan(list(self.visible_rows)) if accepted else None,
        )

    def _begin_scan(self, rows: list[dict[str, Any]]) -> None:
        profile = str(self.query_one("#profile-filter", Select).value)
        self.report_profile = profile
        self._show_view("progress")
        self.query_one("#progress-message", Static).update(f"Queued {len(rows)} installation(s)…")
        self.run_local_scan(rows, profile)

    @work(thread=True, exclusive=True, group="scan")
    def run_local_scan(self, rows: list[dict[str, Any]], profile: str) -> None:
        try:
            raw, view = scan_installed(
                rows,
                profile=profile,
                progress=lambda message: self.call_from_thread(self._update_progress, message),
            )
        except Exception as exc:  # worker boundary: convert expected scanner failures to product UI
            self.call_from_thread(self._scan_failed, str(exc))
            return
        self.call_from_thread(self._scan_complete, raw, view)

    def _update_progress(self, message: str) -> None:
        self.query_one("#progress-message", Static).update(message)

    def _scan_failed(self, message: str) -> None:
        self._show_view("picker")
        self.notify(f"Scan failed: {message}", severity="error", timeout=10)

    def _scan_complete(self, raw: dict[str, Any], view: dict[str, Any]) -> None:
        self.raw_report = raw
        self.view_report = view
        decision = _overall_decision(view)
        summary = Text()
        summary.append(decision.upper(), style=f"bold {_decision_color(decision)}")
        summary.append(f"  {_next_action(decision)}", style="#eef3f6")
        self.query_one("#outcome-summary", Static).update(summary)
        self.query_one("#report-document", Static).update(RichMarkdown(_report_details_markdown(view)))
        self._show_view("results")

    def _show_view(self, name: str) -> None:
        self.query_one("#filters").display = name == "picker"
        self.query_one("#workspace").display = name == "picker"
        self.query_one("#secondary-actions").display = name == "picker"
        self.query_one("#progress-view").display = name == "progress"
        self.query_one("#results-view").display = name == "results"

    @on(Button.Pressed)
    def button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "scan-selected":
            self.action_scan_selected()
        elif button_id == "scan-matches":
            self.action_scan_matches()
        elif button_id == "back-to-picker":
            self._show_view("picker")
        elif button_id.startswith("export-"):
            self.export_current_report(button_id.removeprefix("export-"))
        elif button_id == "scan-file":
            self.push_screen(PathScreen("Scan local extension", "VSIX, ZIP, or extension folder"), self._file_chosen)
        elif button_id == "open-report":
            self.push_screen(PathScreen("Open saved report", "ZIP or JSON report path"), self._report_chosen)
        elif button_id in {"doctor", "rules"}:
            self.exit(TuiResult(button_id))
        elif button_id == "help":
            self.action_help()

    def _file_chosen(self, value: str | None) -> None:
        if value:
            self.exit(TuiResult("file", value))

    def _report_chosen(self, value: str | None) -> None:
        if value:
            self.exit(TuiResult("report", value))

    @work(thread=True, exclusive=False, group="export")
    def export_current_report(self, fmt: str) -> None:
        if self.raw_report is None or self.view_report is None:
            self.call_from_thread(self.notify, "No completed report is available.", severity="warning")
            return
        extension = {"html": "html", "zip": "zip", "json": "json", "md": "md"}[fmt]
        scan_id = str((self.view_report.get("metadata") or {}).get("scan_id") or "scan")
        safe_id = "".join(char if char.isalnum() or char in "-_" else "-" for char in scan_id).strip("-") or "scan"
        output = Path.cwd() / f"guardrails-{safe_id}.{extension}"
        try:
            if fmt == "html":
                export_html(self.view_report, output)
            elif fmt == "md":
                export_markdown(self.view_report, output)
            elif fmt == "json":
                export_json(self.raw_report, output)
            else:
                write_bundle(self.raw_report, output, source="installed", profile=self.report_profile)
                valid, errors = validate_report(output)
                if not valid:
                    raise ValueError("Report verification failed: " + "; ".join(errors[:3]))
        except Exception as exc:
            self.call_from_thread(self.notify, f"Export failed: {exc}", severity="error", timeout=10)
            return
        self.call_from_thread(self.notify, f"Saved {fmt.upper()} · {output}", severity="information", timeout=10)


def launch(rows: list[dict[str, Any]]) -> TuiResult | None:
    return GuardrailsApp(rows).run()


def _row_key(row: dict[str, Any]) -> str:
    return str(row.get("path") or f"{row.get('client')}:{row.get('extension_id')}:{row.get('version')}")


def _search_text(row: dict[str, Any]) -> str:
    return " ".join(
        str(row.get(key) or "")
        for key in ("display_name", "extension_id", "publisher", "client", "version")
    ).lower()


def _row_prompt(row: dict[str, Any]) -> Text:
    name = _display_name(row)
    identity = f"{row.get('extension_id', 'unknown')}@{row.get('version', 'unknown')}"
    client = str(row.get("client") or "IDE")
    prompt = Text()
    prompt.append(name, style="bold #eef3f6")
    prompt.append(f"  {identity}", style="#8fa0ad")
    prompt.append(f"  {client}", style="#17aefd")
    return prompt


def _display_name(row: dict[str, Any]) -> str:
    name = str(row.get("display_name") or "").strip()
    if name and not (name.startswith("%") and name.endswith("%")):
        return name
    identifier = str(row.get("extension_id") or "Unknown")
    leaf = identifier.rsplit(".", 1)[-1]
    return leaf.replace("-", " ").replace("_", " ").title()


def _overall_decision(report: dict[str, Any]) -> str:
    decisions = {
        str(item.get("decision") or "incomplete").lower()
        for item in report.get("extensions", [])
        if isinstance(item, dict)
    }
    return next((value for value in ("block", "incomplete", "review", "allow") if value in decisions), "incomplete")


def _decision_color(decision: str) -> str:
    return {"allow": "#47c978", "review": "#f5b942", "block": "#ff5a68", "incomplete": "#a78bfa"}[decision]


def _next_action(decision: str) -> str:
    return {
        "allow": "No action is required for this scan.",
        "review": "Review the highlighted evidence before keeping these extensions enabled.",
        "block": "Disable blocked extensions and review the evidence before restoring them.",
        "incomplete": "Resolve required provider coverage, then scan again.",
    }[decision]


def _report_details_markdown(report: dict[str, Any]) -> str:
    document = to_markdown(report)
    marker = "## Decisions"
    position = document.find(marker)
    return document[position:] if position >= 0 else document
