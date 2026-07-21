from __future__ import annotations

import unittest

from textual.widgets import Input, SelectionList

from guardrails_cli.tui import GuardrailsApp, _display_name, _overall_decision


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


if __name__ == "__main__":
    unittest.main()
