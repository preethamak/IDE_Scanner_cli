from __future__ import annotations

import unittest

from guardrails_cli.exporters.sarif import to_sarif


class SarifExportTests(unittest.TestCase):
    def test_projects_exact_release_findings_without_inventing_file_locations(self) -> None:
        sarif = to_sarif({"metadata": {"scan_id": "scan-1", "scanner_build": "build-1"}, "extensions": [{"extension_id": "sample.extension", "version": "1.2.3", "decision": "review", "artifact_sha256": "a" * 64, "findings": [{"rule_id": "network-request", "severity": "high", "evidence_summary": "Observed network request."}]}]})
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["properties"]["artifact_sha256"], "a" * 64)
        self.assertIn("logicalLocations", result["locations"][0])
        self.assertNotIn("physicalLocation", result["locations"][0])
