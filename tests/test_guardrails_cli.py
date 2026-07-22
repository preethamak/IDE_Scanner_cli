from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from guardrails_cli import main as cli
from guardrails_cli.ui.prompts import prompt_choice


class GuardrailsCliTests(unittest.TestCase):
    def run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_version_uses_guardrails_brand(self) -> None:
        code, output, error = self.run_cli(["version"])
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.assertIn("Guardrails 0.3.2", output)

    def test_standard_version_flag_is_supported(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            cli.main(["--version"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("Guardrails 0.3.2", output.getvalue())

    def test_help_manual_explains_commands_and_shortcuts(self) -> None:
        code, output, error = self.run_cli(["help"])
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.assertIn("Command map", output)
        self.assertIn("guardrails help shortcuts", output)

        code, output, error = self.run_cli(["help", "automation"])
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.assertIn("Exit codes", output)

    def test_noninteractive_installed_scan_requires_selection(self) -> None:
        rows = [{"client": "VS Code", "path": "/tmp/ext", "extension_id": "one.ext", "display_name": "One", "publisher": "one", "version": "1.0.0"}]
        with patch("guardrails_cli.main.installed_extensions", return_value=rows), patch("guardrails_cli.main.sys.stdin.isatty", return_value=False):
            code, _output, error = self.run_cli(["scan"])
        self.assertEqual(code, 2)
        self.assertIn("--all, --extension, or --select", error)

    def test_tui_requires_an_interactive_terminal(self) -> None:
        code, _output, error = self.run_cli(["tui"])
        self.assertEqual(code, 2)
        self.assertIn("requires a terminal", error)

    def test_missing_report_is_a_product_error_not_a_traceback(self) -> None:
        code, _output, error = self.run_cli(["report", "view", "/tmp/guardrails-missing-report.zip"])
        self.assertEqual(code, 2)
        self.assertIn("Report does not exist", error)
        self.assertNotIn("Traceback", error)

    def test_invalid_offline_online_combination_is_rejected(self) -> None:
        code, _output, error = self.run_cli(["scan", "--all", "--profile", "offline", "--online"])
        self.assertEqual(code, 2)
        self.assertIn("cannot be combined", error)

    def test_installed_search_filters_before_selection(self) -> None:
        rows = [
            {"client": "VS Code", "path": "/tmp/one", "extension_id": "sample.one", "display_name": "Alpha", "publisher": "sample", "version": "1.0.0"},
            {"client": "Cursor", "path": "/tmp/two", "extension_id": "sample.two", "display_name": "Solidity Tools", "publisher": "sample", "version": "2.0.0"},
        ]
        args = cli._scan_namespace(search="solidity", all=True)
        with patch("guardrails_cli.main.installed_extensions", return_value=rows), redirect_stdout(io.StringIO()):
            selected = cli._select_installed(args)
        self.assertEqual([item["extension_id"] for item in selected], ["sample.two"])

    def test_picker_is_bounded_and_searchable_for_large_inventories(self) -> None:
        rows = [
            {"client": "VS Code", "path": f"/tmp/{index}", "extension_id": f"sample.ext-{index}", "display_name": f"Extension {index}", "publisher": "sample", "version": "1.0.0"}
            for index in range(100)
        ]
        rows[73]["display_name"] = "Solidity Tools"
        output = io.StringIO()
        with patch("builtins.input", side_effect=["/solidity", "1", "d"]), redirect_stdout(output):
            selected = cli._interactive_installed_picker(rows)
        self.assertEqual([item["extension_id"] for item in selected], ["sample.ext-73"])
        self.assertIn("100 detected", output.getvalue())
        self.assertIn("1 match", output.getvalue())
        self.assertNotIn("Extension 99", output.getvalue())

    def test_fail_on_policy_has_stable_exit_codes(self) -> None:
        block = {"extensions": [{"decision": "block"}]}
        review = {"extensions": [{"decision": "review"}]}
        incomplete = {"extensions": [{"decision": "incomplete"}]}
        self.assertEqual(cli._scan_exit_code(block, "block"), 1)
        self.assertEqual(cli._scan_exit_code(review, "block"), 0)
        self.assertEqual(cli._scan_exit_code(review, "review"), 1)
        self.assertEqual(cli._scan_exit_code(incomplete, "never"), 3)

    def test_export_menu_prints_numbered_formats_before_prompting(self) -> None:
        choices = ["HTML — readable report (recommended)", "ZIP — verifiable evidence bundle", "Skip export"]
        output = io.StringIO()
        with patch("builtins.input", return_value="2"), redirect_stdout(output):
            selected = prompt_choice("Choose export format", choices)
        self.assertEqual(selected, 1)
        self.assertIn("1  HTML", output.getvalue())
        self.assertIn("2  ZIP", output.getvalue())
        self.assertIn("3  Skip", output.getvalue())

    def test_fresh_html_export_builds_its_presentation_model(self) -> None:
        report = {"scan_id": "scan-1", "summary": {}, "extensions": []}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            cli._export_fresh(report, "html", str(output), source="installed", profile="standard")
            content = output.read_text(encoding="utf-8")
        self.assertIn("Guardrails", content)


if __name__ == "__main__":
    unittest.main()
