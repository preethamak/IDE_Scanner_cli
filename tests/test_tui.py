from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from textual.widgets import DataTable, Input, SelectionList, Static

from guardrails_cli.tui import GuardrailsApp, HelpApp, _display_name, _overall_decision


ROWS = [
    {
        "client": "VS Code",
        "path": "/tmp/one",
        "extension_id": "sample.one",
        "display_name": "Alpha Tools",
        "publisher": "sample",
        "version": "1.0.0",
    },
    {
        "client": "Cursor",
        "path": "/tmp/two",
        "extension_id": "sample.two",
        "display_name": "Solidity Tools",
        "publisher": "sample",
        "version": "2.0.0",
    },
]


class GuardrailsTuiTests(unittest.IsolatedAsyncioTestCase):
    async def test_live_search_and_selection_need_no_command_input(self) -> None:
        self.assertIn(".narrow #detail-pane", GuardrailsApp.CSS)
        self.assertTrue(any(binding.key == "?" and binding.action == "help" for binding in GuardrailsApp.BINDINGS))
        app = GuardrailsApp(ROWS)
        async with app.run_test(size=(100, 32)) as pilot:
            listing = app.query_one("#extensions", SelectionList)
            self.assertEqual(listing.option_count, 2)
            search = app.query_one("#search", Input)
            search.focus()
            await pilot.press(*"solidity")
            await pilot.pause()
            self.assertEqual(listing.option_count, 1)
            listing.select("/tmp/two")
            await pilot.pause()
            self.assertEqual(app.selected_keys, {"/tmp/two"})

    def test_unresolved_manifest_labels_do_not_leak_into_the_ui(self) -> None:
        row = {"display_name": "%displayName%", "extension_id": "sample.remote-containers"}
        self.assertEqual(_display_name(row), "Remote Containers")

    def test_result_banner_uses_security_decision_priority(self) -> None:
        report = {"extensions": [{"decision": "allow"}, {"decision": "block"}, {"decision": "review"}]}
        self.assertEqual(_overall_decision(report), "block")

    async def test_results_expose_scores_findings_copy_and_export_location(self) -> None:
        extension = {
            "extension_id": "sample.two",
            "version": "2.0.0",
            "client": "Cursor",
            "decision": "review",
            "decision_reason": "One high-confidence behavior needs review.",
            "risk_score": 72,
            "malware_score": 38,
            "analysis_coverage": {
                "coverage_percent": 90,
                "providers": {"native_static": {"status": "completed", "required": True}},
            },
            "findings": [
                {
                    "severity": "HIGH",
                    "rule_id": "PROCESS_EXECUTION",
                    "evidence_summary": "The extension starts a child process.",
                    "evidence_class": "static-code",
                    "file_refs": ["extension.js:12"],
                }
            ],
            "artifact_sha256": "a" * 64,
        }
        view = {"metadata": {"scan_id": "scan-1"}, "extensions": [extension]}
        app = GuardrailsApp(ROWS)
        async with app.run_test(size=(120, 32)) as pilot:
            app._scan_complete(view, view)
            await pilot.pause()
            self.assertEqual(app.query_one("#result-table", DataTable).row_count, 1)
            self.assertGreaterEqual(app.query_one("#report-scroll").region.height, 14)
            detail = str(app.query_one("#report-detail", Static).render())
            self.assertIn("Malware evidence", detail)
            self.assertIn("PROCESS_EXECUTION", detail)
            self.assertIn("extension.js:12", detail)
            app.action_copy_context()
            self.assertIn("sample.two", app.clipboard)
            with TemporaryDirectory() as directory:
                exported = Path(directory) / "report.html"
                exported.touch()
                app._export_completed("html", exported)
                receipt = str(app.query_one("#export-status", Static).render())
                self.assertIn(str(exported.resolve()), receipt)

    async def test_help_is_a_branded_topic_application_and_can_be_copied(self) -> None:
        app = HelpApp("reports")
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            self.assertEqual(app.topic, "reports")
            self.assertIn("G U A R D R A I L S", str(app.query_one("#manual-wordmark", Static).render()))
            app.action_copy_manual()
            self.assertIn("# Reports", app.clipboard)


if __name__ == "__main__":
    unittest.main()
