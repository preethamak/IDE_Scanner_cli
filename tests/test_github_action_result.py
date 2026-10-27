from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "github_action_result.py"
SPEC = importlib.util.spec_from_file_location("github_action_result", SCRIPT)
assert SPEC and SPEC.loader
result = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(result)


class GitHubActionResultTests(unittest.TestCase):
    def test_summary_uses_worst_decision_and_coverage_floor(self) -> None:
        summary = result.report_summary({"extensions": [
            {"decision": "allow", "status": "complete", "analysis_coverage": {"status": "complete", "coverage_percent": 100}},
            {"decision": "review", "status": "complete", "analysis_coverage": {"status": "complete", "coverage_percent": 87}},
        ]})
        self.assertEqual(summary["decision"], "review")
        self.assertEqual(summary["coverage_percent"], 87)
        self.assertTrue(summary["complete"])

    def test_summary_fails_closed_for_missing_or_incomplete_reports(self) -> None:
        self.assertEqual(result.report_summary({})["decision"], "incomplete")
        summary = result.report_summary({"extensions": [{"decision": "allow", "status": "incomplete", "analysis_coverage": {"status": "incomplete"}}]})
        self.assertFalse(summary["complete"])

    def test_markdown_contains_exact_artifact_identity_without_full_hash(self) -> None:
        content = result.markdown({"decision": "block", "extension_count": 1, "coverage_percent": 100, "complete": True, "extensions": [{"extension_id": "sample.extension", "version": "1.2.3", "decision": "block", "artifact_identity": {"sha256": "a" * 64}}]}, "report.json", 1)
        self.assertIn("sample.extension@1.2.3", content)
        self.assertIn("SHA-256 aaaaaaaaaaaa...", content)
        self.assertNotIn("a" * 64, content)
