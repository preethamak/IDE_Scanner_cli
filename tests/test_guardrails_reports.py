from __future__ import annotations

import json
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from guardrails_cli.report_reader import report_view, validate_report
from guardrails_cli.exporters.html import to_html
from guardrails_cli.scanner_adapter import write_bundle
from guardrails_cli.ui.panels import LOGO_PIXELS


class GuardrailsReportTests(unittest.TestCase):
    def test_empty_json_is_not_a_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.json"
            path.write_text("{}", encoding="utf-8")
            ok, errors = validate_report(path)
        self.assertFalse(ok)
        self.assertIn("extensions list", " ".join(errors))

    def test_view_preserves_every_leaderboard_installation(self) -> None:
        data = {
            "metadata": {"scan_id": "scan-1"},
            "summary": {"summary": {"total_extensions": 2}},
            "leaderboard": {"extensions": [
                {"extension_id": "same.ext", "version": "1.0.0", "decision": "allow", "detail_ref": "extensions/same.json"},
                {"extension_id": "same.ext", "version": "1.0.0", "decision": "review", "detail_ref": "extensions/same.json"},
            ]},
            "details": {"extensions/same.json": {"extension_id": "same.ext", "version": "1.0.0", "findings": []}},
        }
        view = report_view(data)
        self.assertEqual(len(view["extensions"]), 2)
        self.assertEqual([item["decision"] for item in view["extensions"]], ["allow", "review"])

    def test_duplicate_zip_entries_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("metadata.json", json.dumps({"scan_id": "one"}))
                    archive.writestr("metadata.json", json.dumps({"scan_id": "two"}))
            ok, errors = validate_report(path)
        self.assertFalse(ok)
        self.assertIn("duplicate entry", " ".join(errors).lower())

    def test_html_uses_the_same_sampled_brand_mark_as_the_terminal(self) -> None:
        report = {"metadata": {"scan_id": "scan-1"}, "summary": {}, "extensions": []}
        output = to_html(report)
        colored_pixels = sum(pixel is not None for row in LOGO_PIXELS for pixel in row)
        self.assertEqual(output.count('<i style="background:'), colored_pixels)
        self.assertIn("#f13b72", output)
        self.assertIn("#17aefd", output)

    def test_installed_bundle_keeps_the_ide_client(self) -> None:
        report = {"extensions": [{"extension_id": "sample.ext", "version": "1.0.0", "source": "vscode", "client": "Cursor"}]}
        with patch("guardrails_cli.scanner_adapter.write_report_bundle", return_value={}) as writer:
            write_bundle(report, "/tmp/report.zip", source="installed")
        bundled = writer.call_args.args[0]
        self.assertEqual(bundled["extensions"][0]["source"], "Cursor")
        self.assertEqual(report["extensions"][0]["source"], "vscode")


if __name__ == "__main__":
    unittest.main()
