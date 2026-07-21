from __future__ import annotations

import base64
import json
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from importlib.resources import files

from guardrails_cli.report_reader import report_view, validate_report
from guardrails_cli.exporters.html import to_html
from guardrails_cli.exporters.markdown import to_markdown
from guardrails_cli.scanner_adapter import write_bundle


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

    def test_html_embeds_the_exact_website_brand_mark(self) -> None:
        report = {"metadata": {"scan_id": "scan-1"}, "summary": {}, "extensions": []}
        output = to_html(report)
        expected = base64.b64encode(files("guardrails_cli").joinpath("assets/guardrails-mark.png").read_bytes()).decode("ascii")
        self.assertIn(f"data:image/png;base64,{expected}", output)

    def test_markdown_leads_with_outcome_before_scan_identity(self) -> None:
        report = {
            "metadata": {"scan_id": "scan-1"},
            "summary": {"decision_counts": {"allow": 1, "review": 1}},
            "extensions": [],
        }
        output = to_markdown(report)
        self.assertLess(output.index("## Outcome: REVIEW"), output.index("## Scan identity"))

    def test_duplicate_cross_ide_installations_round_trip_in_zip(self) -> None:
        report = {"scan_id": "scan-1", "summary": {}, "extensions": [
            {"extension_id": "sample.ext", "name": "ext", "publisher": "sample", "version": "1.0.0", "source": "vscode", "client": "VS Code", "decision": "allow", "verdict": "clean", "severity": "INFO", "findings": []},
            {"extension_id": "sample.ext", "name": "ext", "publisher": "sample", "version": "1.0.0", "source": "cursor", "client": "Cursor", "decision": "review", "verdict": "review", "severity": "MEDIUM", "findings": []},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.zip"
            write_bundle(report, path, source="installed")
            ok, errors = validate_report(path)
            with zipfile.ZipFile(path) as archive:
                leaderboard = json.loads(archive.read("leaderboard.json"))
        self.assertTrue(ok, errors)
        rows = leaderboard["extensions"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row["detail_ref"] for row in rows}), 2)
        self.assertEqual(len({row["installation_id"] for row in rows}), 2)
        self.assertEqual({row["source"] for row in rows}, {"VS Code", "Cursor"})


if __name__ == "__main__":
    unittest.main()
