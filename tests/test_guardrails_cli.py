from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from guardrails_cli import main as cli


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
        self.assertIn("Guardrails 0.1.0", output)

    def test_noninteractive_installed_scan_requires_selection(self) -> None:
        rows = [{"client": "VS Code", "path": "/tmp/ext", "extension_id": "one.ext", "display_name": "One", "publisher": "one", "version": "1.0.0"}]
        with patch("guardrails_cli.main.installed_extensions", return_value=rows), patch("guardrails_cli.main.sys.stdin.isatty", return_value=False):
            code, _output, error = self.run_cli(["scan"])
        self.assertEqual(code, 1)
        self.assertIn("--all, --extension, or --select", error)

    def test_missing_report_is_a_product_error_not_a_traceback(self) -> None:
        code, _output, error = self.run_cli(["report", "view", "/tmp/guardrails-missing-report.zip"])
        self.assertEqual(code, 1)
        self.assertIn("Report does not exist", error)
        self.assertNotIn("Traceback", error)

    def test_invalid_offline_online_combination_is_rejected(self) -> None:
        code, _output, error = self.run_cli(["scan", "--all", "--profile", "offline", "--online"])
        self.assertEqual(code, 1)
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

    def test_duplicate_installations_are_detected_before_zip_export(self) -> None:
        view = {"extensions": [
            {"extension_id": "sample.ext", "version": "1.0.0", "client": "VS Code"},
            {"extension_id": "sample.ext", "version": "1.0.0", "client": "Cursor"},
        ]}
        self.assertEqual(cli._duplicate_installation_identities(view), [("sample.ext", "1.0.0")])


if __name__ == "__main__":
    unittest.main()
