from __future__ import annotations
import unittest
from guardrails_cli.report_diff import compare_reports
class ReportDiffTests(unittest.TestCase):
    def test_compares_exact_release_identity_and_rule_changes(self) -> None:
        result = compare_reports({"extensions": [{"extension_id": "sample.extension", "version": "1", "decision": "allow", "findings": []}]}, {"extensions": [{"extension_id": "sample.extension", "version": "2", "decision": "review", "findings": [{"rule_id": "network-request"}]}]})
        self.assertEqual(result["changed"], 1); self.assertEqual(result["extensions"][0]["fields"]["decision"], ["allow", "review"]); self.assertEqual(result["extensions"][0]["added_rule_ids"], ["network-request"])
