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
    DataTable,
    Footer,
    Input,
    Label,
    Link,
    Select,
    SelectionList,
    Static,
)

from .exporters.html import export_html
from .exporters.json_export import export_json
from .exporters.markdown import export_markdown, to_markdown
from .help_manual import TOPICS, interactive_manual, manual
from .report_reader import validate_report
from .scan_service import scan_installed
from .scanner_adapter import write_bundle
from .ui.panels import LOGO_PIXELS


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
                yield Static(RichMarkdown(_rich_manual(interactive_manual())), classes="markdown-content")
            yield Button("Close", id="close-help", variant="primary")

    def action_dismiss(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#close-help")
    def close_help(self) -> None:
        self.dismiss(None)


class HelpApp(App[None]):
    TITLE = "Guardrails Manual"
    SUB_TITLE = "Local Scan"

    CSS = """
    $surface: #14202b;
    $ink: #eef3f6;
    $muted: #8fa0ad;
    $brand: #c9ff45;

    Screen { background: #0c1218; color: $ink; }
    #manual-hero { height: 7; padding: 0 2; background: $surface; border-bottom: solid $brand; }
    #manual-mark { width: 13; height: 6; padding-top: 1; }
    #manual-brand { width: 1fr; height: 6; padding: 1 1 0 1; }
    #manual-wordmark { height: 2; text-style: bold; }
    #manual-title { height: 1; color: $brand; }
    #manual-subtitle { height: 1; color: $muted; }
    #manual-toolbar { height: 5; padding: 1 2; background: #101a22; }
    #manual-topic { width: 34; margin-right: 1; }
    #manual-toolbar-note { width: 1fr; padding: 1; color: $muted; }
    #copy-manual { min-width: 14; }
    Select { border: tall #385060; background: $surface; }
    Select:focus { border: tall $brand; }
    Button.-primary { background: $brand; color: #14202b; }
    #manual-layout { height: 1fr; padding: 1 2; }
    #manual-nav { width: 26; height: 1fr; margin-right: 1; padding: 1 2; background: $surface; border: round #385060; color: $muted; }
    #manual-document { width: 1fr; height: 1fr; padding: 1 3; background: $surface; border: round #385060; }
    #manual-content { height: auto; }
    Footer { background: $surface; }
    .narrow #manual-hero { height: 6; padding: 0 1; }
    .narrow #manual-mark { width: 12; height: 5; padding-top: 0; }
    .narrow #manual-brand { height: 5; padding-top: 0; }
    .narrow #manual-toolbar { padding: 1; }
    .narrow #manual-topic { width: 1fr; }
    .narrow #manual-toolbar-note { display: none; }
    .narrow #manual-layout { padding: 1; }
    .narrow #manual-nav { display: none; }
    .narrow #manual-document { width: 100%; padding: 1 2; }
    """

    BINDINGS = [
        Binding("ctrl+c", "copy_manual", "Copy manual"),
        Binding("escape", "quit", "Close"),
        Binding("q", "quit", "Close"),
    ]

    def __init__(self, topic: str | None = None) -> None:
        super().__init__()
        self.topic = topic

    def compose(self) -> ComposeResult:
        with Horizontal(id="manual-hero"):
            yield Static(_textual_brand_mark(), id="manual-mark")
            with Vertical(id="manual-brand"):
                yield Static("G U A R D R A I L S", id="manual-wordmark")
                yield Static("COMMAND MANUAL", id="manual-title")
                yield Static("Clear workflows, flags, reports, and shortcuts", id="manual-subtitle")
        with Horizontal(id="manual-toolbar"):
            yield Select(
                [("Overview", "overview"), *((name.title(), name) for name in TOPICS)],
                value=self.topic or "overview",
                allow_blank=False,
                id="manual-topic",
            )
            yield Static("Choose a topic. Use Tab to move and Up/Down to read.", id="manual-toolbar-note")
            yield Button("Copy manual", id="copy-manual", variant="primary")
        with Horizontal(id="manual-layout"):
            yield Static(
                "[b #c9ff45]QUICK REFERENCE[/b #c9ff45]\n\n"
                "scan       Start a security scan\n"
                "report     Open or verify results\n"
                "rules      Browse detections\n"
                "metrics    Understand scoring\n"
                "doctor     Check readiness\n\n"
                "[b]Tip[/b]\nRun [#17aefd]guardrails help TOPIC[/#17aefd] to open a section directly.",
                id="manual-nav",
            )
            with VerticalScroll(id="manual-document"):
                yield Static(RichMarkdown(_rich_manual(manual(self.topic))), id="manual-content")
        yield Footer()

    def on_mount(self) -> None:
        self._set_responsive_state(self.size.width)

    def on_resize(self, event: Resize) -> None:
        self._set_responsive_state(event.size.width)

    def _set_responsive_state(self, width: int) -> None:
        self.screen.set_class(width < 90, "narrow")

    @on(Select.Changed, "#manual-topic")
    def topic_changed(self, event: Select.Changed) -> None:
        selected = str(event.value)
        self.topic = None if selected == "overview" else selected
        self.query_one("#manual-content", Static).update(RichMarkdown(_rich_manual(manual(self.topic))))
        self.query_one("#manual-document", VerticalScroll).scroll_home(animate=False)

    @on(Button.Pressed, "#copy-manual")
    def copy_button(self) -> None:
        self.action_copy_manual()

    def action_copy_manual(self) -> None:
        self.copy_to_clipboard(manual(self.topic))
        self.notify("Manual copied to the clipboard.", timeout=6)


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

    #primary-actions {
        height: 3;
        margin-top: 1;
    }

    #report-actions {
        height: 1;
        margin-top: 1;
    }

    #report-actions Button {
        height: 1;
        min-width: 10;
        padding: 0 1;
        border: none;
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
        padding: 0 2;
    }

    #outcome-summary {
        height: 3;
        padding: 0 2;
        margin-bottom: 1;
        background: $surface;
        border-left: thick $brand;
    }

    #score-row { height: 5; margin-bottom: 1; }

    .score-card {
        width: 1fr;
        height: 5;
        margin-right: 1;
        padding: 0 2;
        background: $surface;
        border: round #385060;
    }

    #report-workspace { height: 1fr; }

    #result-table {
        width: 2fr;
        height: 1fr;
        margin-right: 1;
        background: $surface;
        border: round #385060;
    }

    #report-scroll {
        width: 3fr;
        height: 1fr;
        padding: 1 2;
        background: $surface;
        border: round #385060;
    }

    #report-detail, .markdown-content { height: auto; }

    #export-receipt {
        display: none;
        height: 5;
        margin-top: 1;
        padding: 0 1;
        background: $surface;
        border-left: thick $cyan;
    }

    #export-status { width: 1fr; height: 4; padding: 1; color: $muted; }
    #export-link { width: 24; height: 3; padding: 1; color: $cyan; }
    #copy-export-path, #open-export { min-width: 13; }

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

    .results-mode #hero { display: none; }
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
    .narrow #outcome-summary { height: 3; padding: 0 2; }
    .narrow #score-row { height: 5; }
    .narrow .score-card { height: 5; padding: 0 1; }
    .narrow #report-workspace { layout: vertical; }
    .narrow #result-table { width: 100%; height: 5; margin: 0 0 1 0; }
    .narrow #report-scroll { width: 100%; height: 1fr; }
    .narrow #export-link { display: none; }
    """

    BINDINGS = [
        Binding("ctrl+s", "scan_selected", "Scan selected", priority=True),
        Binding("ctrl+a", "scan_matches", "Scan matches", priority=True),
        Binding("/", "focus_search", "Search", priority=True),
        Binding("?", "help", "Help", priority=True),
        Binding("ctrl+c", "copy_context", "Copy"),
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
        self.result_rows: dict[str, dict[str, Any]] = {}
        self.last_export: Path | None = None
        self.last_export_format = ""

    def compose(self) -> ComposeResult:
        with Horizontal(id="hero"):
            yield Static(_textual_brand_mark(), id="brand-mark")
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
            with Horizontal(id="score-row"):
                yield Static("", id="risk-score", classes="score-card")
                yield Static("", id="malware-score", classes="score-card")
                yield Static("", id="coverage-score", classes="score-card")
                yield Static("", id="finding-score", classes="score-card")
            with Horizontal(id="report-workspace"):
                yield DataTable(id="result-table", cursor_type="row", zebra_stripes=True)
                with VerticalScroll(id="report-scroll"):
                    yield Static("", id="report-detail")
            with Horizontal(id="report-actions"):
                yield Button("Back", id="back-to-picker")
                yield Button("Save HTML", id="export-html", variant="primary")
                yield Button("Save ZIP", id="export-zip")
                yield Button("Save JSON", id="export-json")
                yield Button("Save Markdown", id="export-md")
                yield Button("Copy report", id="copy-report")
            with Horizontal(id="export-receipt"):
                yield Static("", id="export-status")
                yield Link("Open exported report ↗", url="", id="export-link")
                yield Button("Copy path", id="copy-export-path")
                yield Button("Open", id="open-export")
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

    def action_copy_context(self) -> None:
        if self.view_report is not None and self.query_one("#results-view").display:
            self.copy_to_clipboard(to_markdown(self.view_report))
            self.notify("Complete report copied to the clipboard.", timeout=6)
            return
        listing = self.query_one("#extensions", SelectionList)
        if listing.highlighted is not None and self.visible_rows:
            row = self.visible_rows[listing.highlighted]
            self.copy_to_clipboard(f"{row.get('extension_id')}@{row.get('version')}")
            self.notify("Extension identity copied to the clipboard.", timeout=6)

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
        summary.append("  ·  ", style="#8fa0ad")
        summary.append(_next_action(decision), style="#eef3f6")
        self.query_one("#outcome-summary", Static).update(summary)
        extensions = _rank_report_extensions(view)
        maximum_risk = max((int(item.get("risk_score") or 0) for item in extensions), default=0)
        maximum_malware = max((int(item.get("malware_score") or 0) for item in extensions), default=0)
        average_coverage = round(sum(_coverage(item) for item in extensions) / len(extensions)) if extensions else 0
        finding_count = sum(len(item.get("findings") or []) for item in extensions)
        self.query_one("#risk-score", Static).update(_gauge("RISK SCORE", maximum_risk, "#f5b942"))
        self.query_one("#malware-score", Static).update(_gauge("MALWARE SCORE", maximum_malware, "#ff5a68"))
        self.query_one("#coverage-score", Static).update(_gauge("COVERAGE", average_coverage, "#17aefd", suffix="%"))
        self.query_one("#finding-score", Static).update(_finding_card(finding_count, len(extensions)))
        self._populate_result_table(extensions)
        self.query_one("#export-receipt").display = False
        self._show_view("results")

    def _populate_result_table(self, extensions: list[dict[str, Any]]) -> None:
        table = self.query_one("#result-table", DataTable)
        table.clear(columns=True)
        table.add_columns("Decision", "Extension", "Risk", "Findings")
        self.result_rows = {}
        for index, extension in enumerate(extensions):
            key = f"result-{index}"
            self.result_rows[key] = extension
            decision = _extension_decision(extension)
            label = Text(decision.upper(), style=f"bold {_decision_color(decision)}")
            identity = f"{extension.get('extension_id', 'unknown')}@{extension.get('version', 'unknown')}"
            table.add_row(
                label,
                identity,
                f"{int(extension.get('risk_score') or 0)}/100",
                str(len(extension.get("findings") or [])),
                key=key,
            )
        if extensions:
            table.move_cursor(row=0)
            self._show_report_extension(extensions[0])
        else:
            self.query_one("#report-detail", Static).update("No extension result was recorded.")

    @on(DataTable.RowHighlighted, "#result-table")
    def result_highlighted(self, event: DataTable.RowHighlighted) -> None:
        extension = self.result_rows.get(str(event.row_key.value))
        if extension:
            self._show_report_extension(extension)

    def _show_report_extension(self, extension: dict[str, Any]) -> None:
        self.query_one("#report-detail", Static).update(_extension_report_text(extension))

    def _show_view(self, name: str) -> None:
        self.screen.set_class(name == "results", "results-mode")
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
        elif button_id == "copy-report":
            self.action_copy_context()
        elif button_id == "copy-export-path":
            self._copy_export_path()
        elif button_id == "open-export":
            self._open_last_export()
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
        self.call_from_thread(self._export_completed, fmt, output)

    def _export_completed(self, fmt: str, output: Path) -> None:
        self.last_export = output.resolve()
        self.last_export_format = fmt
        action = "Open report" if fmt == "html" else "Open folder"
        self.query_one("#export-status", Static).update(
            f"Saved {fmt.upper()}\n{self.last_export}"
        )
        link = self.query_one("#export-link", Link)
        link.text = f"{action} ↗"
        link.url = (self.last_export if fmt == "html" else self.last_export.parent).as_uri()
        self.query_one("#open-export", Button).label = action
        self.query_one("#export-receipt").display = True
        self.notify(f"Saved to {self.last_export}", timeout=10)

    def _copy_export_path(self) -> None:
        if self.last_export is None:
            self.notify("Export a report first.", severity="warning")
            return
        self.copy_to_clipboard(str(self.last_export))
        self.notify("Export path copied to the clipboard.", timeout=6)

    def _open_last_export(self) -> None:
        if self.last_export is None:
            self.notify("Export a report first.", severity="warning")
            return
        target = self.last_export if self.last_export_format == "html" else self.last_export.parent
        self.open_url(target.as_uri())


def launch(rows: list[dict[str, Any]]) -> TuiResult | None:
    return GuardrailsApp(rows).run()


def launch_help(topic: str | None = None) -> None:
    HelpApp(topic).run()


def _textual_brand_mark() -> Text:
    """Render the website mark directly with Rich colours, independent of shell ANSI detection."""
    pixels = tuple(tuple(row[index] for index in range(0, len(row), 2)) for row in LOGO_PIXELS[::2])
    mark = Text()
    for row_index in range(0, len(pixels), 2):
        if row_index:
            mark.append("\n")
        for top, bottom in zip(pixels[row_index], pixels[row_index + 1]):
            if top and bottom:
                mark.append("▀", style=f"{top} on {bottom}")
            elif top:
                mark.append("▀", style=top)
            elif bottom:
                mark.append("▄", style=bottom)
            else:
                mark.append(" ")
    return mark


def _rich_manual(source: str) -> str:
    """Promote the manual's terminal-indented examples to Markdown code blocks."""
    return "\n".join(f"  {line}" if line.startswith("  ") else line for line in source.splitlines())


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


def _rank_report_extensions(report: dict[str, Any]) -> list[dict[str, Any]]:
    priority = {"allow": 1, "review": 2, "incomplete": 3, "block": 4}
    extensions = [item for item in report.get("extensions", []) if isinstance(item, dict)]
    return sorted(
        extensions,
        key=lambda item: (
            priority[_extension_decision(item)],
            int(item.get("malware_score") or 0),
            int(item.get("risk_score") or 0),
        ),
        reverse=True,
    )


def _extension_decision(extension: dict[str, Any]) -> str:
    value = str(extension.get("decision") or "").lower()
    if value in {"allow", "review", "block", "incomplete"}:
        return value
    return {
        "clean": "allow",
        "review": "review",
        "suspicious": "review",
        "malicious": "block",
    }.get(str(extension.get("verdict") or "").lower(), "incomplete")


def _coverage(extension: dict[str, Any]) -> int:
    if extension.get("coverage_percent") is not None:
        return int(extension.get("coverage_percent") or 0)
    detail = extension.get("analysis_coverage") if isinstance(extension.get("analysis_coverage"), dict) else {}
    return int(detail.get("coverage_percent") or 0)


def _gauge(label: str, value: int, gauge_color: str, *, suffix: str = "/100") -> Text:
    bounded = max(0, min(100, int(value)))
    filled = round(bounded / 10)
    output = Text(label, style="bold #8fa0ad")
    output.append("\n")
    output.append("◜" + "━" * filled, style=f"bold {gauge_color}")
    output.append("┄" * (10 - filled) + "◝", style="#385060")
    output.append(f"\n{bounded}{suffix}", style=f"bold {gauge_color}")
    return output


def _finding_card(findings: int, extensions: int) -> Text:
    output = Text("FINDINGS", style="bold #8fa0ad")
    output.append(f"\n{findings}", style="bold #eef3f6")
    output.append(f"\nacross {extensions} installation{'s' if extensions != 1 else ''}", style="#8fa0ad")
    return output


def _extension_report_text(extension: dict[str, Any]) -> Text:
    decision = _extension_decision(extension)
    extension_id = str(extension.get("extension_id") or "unknown")
    version = str(extension.get("version") or "unknown")
    client = str(extension.get("client") or extension.get("source") or "local")
    reason = str(extension.get("decision_reason") or extension.get("verdict_reason") or "No explanation was recorded.")
    artifact = extension.get("artifact_identity") if isinstance(extension.get("artifact_identity"), dict) else {}
    artifact_sha = str(extension.get("artifact_sha256") or artifact.get("sha256") or extension.get("artifact_hash") or "unavailable")
    risk = int(extension.get("risk_score") or 0)
    malware = int(extension.get("malware_score") or 0)
    coverage = _coverage(extension)

    output = Text()
    output.append(f"{extension_id}@{version}\n", style="bold #eef3f6")
    output.append(f"{decision.upper()}  ", style=f"bold {_decision_color(decision)}")
    output.append(f"{client}  ·  coverage {coverage}%\n", style="#8fa0ad")
    output.append("WHY THIS RESULT\n", style="bold #c9ff45")
    output.append(reason + "\n\n", style="#eef3f6")

    output.append("SECURITY SCORES\n", style="bold #c9ff45")
    output.append(_inline_bar("Risk priority", risk, "#f5b942"))
    output.append("\n")
    output.append(_inline_bar("Malware evidence", malware, "#ff5a68"))
    output.append("\n")
    output.append(_inline_bar("Analysis coverage", coverage, "#17aefd", suffix="%"))
    output.append("\n\n")

    coverage_detail = extension.get("analysis_coverage") if isinstance(extension.get("analysis_coverage"), dict) else {}
    providers = coverage_detail.get("providers") if isinstance(coverage_detail.get("providers"), dict) else {}
    output.append("PROVIDER COVERAGE\n", style="bold #c9ff45")
    if providers:
        for name, raw_detail in providers.items():
            detail = raw_detail if isinstance(raw_detail, dict) else {}
            status = str(detail.get("status") or "unknown")
            required = "required" if detail.get("required") else "optional"
            provider = {
                "native_static": "Native static",
                "javascript_ast": "JavaScript AST",
                "dependency_intelligence": "Dependency advisories",
            }.get(str(name), str(name).replace("_", " ").title())
            status_color = "#47c978" if status == "completed" else "#ff5a68" if required == "required" else "#f5b942"
            output.append("● ", style=status_color)
            output.append(f"{provider}: {status}", style="#eef3f6")
            output.append(f"  {required}\n", style="#8fa0ad")
    else:
        output.append("Provider detail was not recorded.\n", style="#8fa0ad")

    findings = [item for item in extension.get("findings", []) if isinstance(item, dict)]
    output.append(f"\nFINDINGS ({len(findings)})\n", style="bold #c9ff45")
    if not findings:
        output.append("No findings were reported for this artifact.\n", style="#47c978")
    for index, finding in enumerate(_rank_findings(findings), start=1):
        severity = str(finding.get("severity") or "INFO").upper()
        rule = str(finding.get("rule_id") or "unknown-rule")
        summary = str(finding.get("evidence_summary") or "No evidence summary was recorded.")
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        evidence_class = str(finding.get("evidence_class") or evidence.get("evidence_class") or "unknown")
        references = [str(value) for value in finding.get("file_refs", []) if value]
        output.append(f"\n{index}. {severity}  ", style=f"bold {_severity_color(severity)}")
        output.append(rule + "\n", style="bold #eef3f6")
        output.append(summary + "\n", style="#eef3f6")
        output.append(f"Evidence: {evidence_class}", style="#8fa0ad")
        if references:
            output.append(f"  ·  {references[0]}", style="#17aefd")
        output.append("\n")

    output.append("\nARTIFACT IDENTITY\n", style="bold #c9ff45")
    output.append(f"SHA-256  {artifact_sha}\n", style="#8fa0ad")
    return output


def _inline_bar(label: str, value: int, bar_color: str, *, suffix: str = "/100") -> Text:
    bounded = max(0, min(100, int(value)))
    filled = round(bounded / 5)
    output = Text(f"{label:<18} ", style="#8fa0ad")
    output.append("█" * filled, style=bar_color)
    output.append("░" * (20 - filled), style="#385060")
    output.append(f"  {bounded}{suffix}", style=f"bold {bar_color}")
    return output


def _rank_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priority = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return sorted(findings, key=lambda item: priority.get(str(item.get("severity") or "INFO").upper(), 0), reverse=True)


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "#ff5a68",
        "HIGH": "#ff5a68",
        "MEDIUM": "#f5b942",
        "LOW": "#17aefd",
        "INFO": "#8fa0ad",
    }.get(severity, "#8fa0ad")
