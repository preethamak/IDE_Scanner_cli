from __future__ import annotations

import re
import os
import unittest
from os import terminal_size
from unittest.mock import patch

from guardrails_cli.ui.renderers import render_scan_report
from guardrails_cli.ui.panels import LOGO_PIXELS, logo_lines
from guardrails_cli.ui.tables import ANSI_RE, table, visible_len
from guardrails_cli.ui.theme import color, severity_label


EMOJI_RE = re.compile(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]")
ALLOWED_SEVERITY_EMOJI: set[str] = set()


class CliUiTests(unittest.TestCase):
    def test_table_respects_requested_width(self) -> None:
        output = table(
            ["Rule", "Meaning"],
            [["credential-dataflow-to-network", "Credential data flow to a network sink should be reviewed immediately."]],
            max_widths=[34, 80],
            width=48,
        )

        self.assertTrue(all(visible_len(line) <= 48 for line in output.splitlines()))
        self.assertIn("╭", output)
        self.assertIn("╰", output)
        self.assertIn("Credential data", output)

    def test_table_alignment_ignores_ansi_codes(self) -> None:
        output = table(["Severity", "Count"], [[color("HIGH", "red"), 3]], max_widths=[10, 6], width=32)
        plain = ANSI_RE.sub("", output)

        self.assertIn("HIGH", plain)
        self.assertTrue(all(visible_len(line) <= 32 for line in output.splitlines()))

    def test_many_column_table_falls_back_to_stacked_layout(self) -> None:
        output = table(
            ["#", "Extension", "Verdict", "Severity", "Risk", "Malware", "Findings"],
            [[1, "publisher.extremely-long-extension-id", "Suspicious", "🟠 HIGH", 78, 45, 12]],
            max_widths=[4, 36, 18, 12, 7, 8, 9],
            width=40,
        )

        self.assertTrue(all(visible_len(line) <= 40 for line in output.splitlines()))
        self.assertIn("Extension", output)
        self.assertIn("Severity", output)

    def test_three_column_table_stacks_in_very_narrow_terminal(self) -> None:
        output = table(
            ["Check", "Status", "Detail"],
            [["Vendored acorn", "OK", "/home/akprajwal/VScode/ide-scanner/src/ide_scanner/js_ast/acorn_vendor.js"]],
            max_widths=[24, 10, 80],
            width=40,
        )

        self.assertTrue(all(visible_len(line) <= 40 for line in output.splitlines()))
        self.assertIn("Check", output)
        self.assertIn("Detail", output)
        self.assertNotIn("...", output)

    def test_table_wraps_long_tokens_without_truncating(self) -> None:
        output = table(
            ["Metric", "Meaning"],
            [["reputation", "Marketplace/repository metadata and trust context."]],
            max_widths=[18, 19],
            width=40,
        )

        self.assertTrue(all(visible_len(line) <= 40 for line in output.splitlines()))
        self.assertIn("Marketplace/", output)
        self.assertIn("repository", output)
        self.assertNotIn("Marketplace/re...", output)

    def test_severity_labels_keep_only_priority_emoji(self) -> None:
        self.assertEqual(severity_label("critical"), "● CRITICAL")
        self.assertEqual(severity_label("high"), "● HIGH")
        self.assertEqual(severity_label("medium"), "● MEDIUM")
        self.assertEqual(severity_label("low"), "LOW")
        self.assertEqual(severity_label("info"), "INFO")

    def test_rendered_report_has_only_severity_emoji(self) -> None:
        report = {
            "scan_id": "scan-1",
            "created_at": "2026-07-08T00:00:00Z",
            "summary": {"total_extensions": 1, "max_risk_score": 40, "max_malware_score": 0},
            "extensions": [{
                "extension_id": "example.notes",
                "name": "Example Notes",
                "version": "1.0.0",
                "publisher": "example",
                "verdict": "review",
                "decision": "review",
                "verdict_label": "Review",
                "severity": "MEDIUM",
                "grade": "C",
                "risk_score": 40,
                "malware_score": 0,
                "context_score": 10,
                "analysis_coverage": {"coverage_percent": 100, "providers": {"native_static": {"status": "completed", "required": True}}},
                "findings": [{
                    "severity": "MEDIUM",
                    "rule_id": "credential-inputbox-prompt",
                    "evidence_class": "exposure",
                    "actionability": "review",
                    "evidence_summary": "Prompts for a credential-like value.",
                    "recommendation": "Confirm the prompt is expected.",
                    "confidence": "medium",
                    "file_refs": ["extension.js"],
                    "category": "cross-extension-exposure",
                }],
            }],
        }

        output = render_scan_report(report)
        emojis = set(EMOJI_RE.findall(output))

        self.assertTrue(emojis <= ALLOWED_SEVERITY_EMOJI)
        self.assertIn("Scan scan-1", output)
        self.assertIn("Guardrails", output)
        self.assertIn("REVIEW", output)
        self.assertIn("Analysis coverage", output)

    def test_rendered_report_respects_narrow_terminal_width(self) -> None:
        report = {
            "scan_id": "scan-with-a-very-long-identifier-1234567890",
            "created_at": "2026-07-08T00:00:00Z",
            "summary": {"total_extensions": 2, "max_risk_score": 78, "max_malware_score": 45},
            "extensions": [
                {
                    "extension_id": "publisher.extremely-long-extension-id-with-many-segments-and-extra-text",
                    "name": "Very Long Extension Display Name That Should Not Overflow The Terminal",
                    "version": "1.0.0",
                    "publisher": "publisher-name-with-long-value",
                    "verdict": "suspicious",
                    "verdict_label": "Suspicious",
                    "severity": "HIGH",
                    "grade": "D",
                    "risk_score": 78,
                    "malware_score": 45,
                    "context_score": 30,
                    "verdict_reason": "Several high signal behaviors combine with broad workspace access and outbound network transfer.",
                    "findings": [{
                        "severity": "HIGH",
                        "rule_id": "credential-dataflow-to-network-with-very-long-rule-id",
                        "evidence_class": "correlated",
                        "actionability": "investigate",
                        "evidence_summary": "Credential data flow to a network sink should be reviewed immediately because the destination and activation path are suspicious.",
                        "recommendation": "Remove or isolate the extension until behavior is confirmed.",
                        "confidence": "high",
                        "file_refs": ["src/very/long/path/to/extension.js:123"],
                        "category": "credential-exfiltration",
                    }],
                },
                {
                    "extension_id": "other.ext",
                    "name": "Other",
                    "version": "2.0.0",
                    "publisher": "other",
                    "verdict": "review",
                    "verdict_label": "Review",
                    "severity": "LOW",
                    "grade": "B",
                    "risk_score": 10,
                    "malware_score": 0,
                    "context_score": 8,
                    "findings": [],
                },
            ],
        }

        with patch("guardrails_cli.ui.tables.shutil.get_terminal_size", return_value=terminal_size((40, 24))):
            output = render_scan_report(report)

        self.assertTrue(all(visible_len(line) <= 40 for line in output.splitlines()))
        self.assertIn("Action required", output)
        self.assertIn("REVIEW", output)
        self.assertIn("publisher.extremely", output)

    def test_report_never_exceeds_common_terminal_widths(self) -> None:
        report = {
            "metadata": {"scan_id": "scan-width", "profile": "standard", "source": "installed"},
            "summary": {},
            "extensions": [{
                "extension_id": "publisher.extension-with-a-long-identity",
                "version": "1.2.3",
                "client": "VS Code Insiders",
                "decision": "review",
                "severity": "HIGH",
                "decision_reason": "This intentionally long decision reason must wrap without crossing the terminal boundary at any supported width.",
                "risk_score": 61,
                "malware_score": 0,
                "coverage_percent": 100,
                "findings": [],
            }],
        }
        for width in (32, 40, 60, 80, 120):
            with self.subTest(width=width), patch("guardrails_cli.ui.tables.shutil.get_terminal_size", return_value=terminal_size((width, 24))):
                output = render_scan_report(report)
            self.assertTrue(all(visible_len(line) <= width for line in output.splitlines()), output)

    def test_truecolor_logo_preserves_square_half_block_geometry(self) -> None:
        with patch.dict(os.environ, {"FORCE_COLOR": "1", "COLORTERM": "truecolor"}, clear=False):
            os.environ.pop("NO_COLOR", None)
            lines = logo_lines()
        self.assertEqual(len(LOGO_PIXELS), 20)
        self.assertEqual(len(lines), 10)
        self.assertTrue(all(visible_len(line) <= 20 for line in lines))


if __name__ == "__main__":
    unittest.main()
