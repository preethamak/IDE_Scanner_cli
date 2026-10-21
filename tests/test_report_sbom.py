from __future__ import annotations

import unittest

from guardrails_cli.report_sbom import build_cyclonedx_sbom


class ReportSbomTests(unittest.TestCase):
    def test_exports_exact_extension_hash_and_runtime_dependencies(self) -> None:
        artifact_hash = "a" * 64
        sbom = build_cyclonedx_sbom(
            {
                "metadata": {"scan_id": "scan-1", "created_at": "2026-10-21T00:00:00Z", "scanner_build": "build-1", "ruleset_version": "rules-1"},
                "summary": {},
                "extensions": [{"extension_id": "publisher.extension", "version": "1.2.3", "artifact_sha256": artifact_hash, "decision": "review", "coverage_percent": 92, "dependencies": {"lodash": "4.17.21"}}],
            }
        )
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        extension = next(item for item in sbom["components"] if item["type"] == "application")
        self.assertEqual(extension["hashes"][0]["content"], artifact_hash)
        self.assertEqual(extension["purl"], "pkg:generic/vscode-extension/publisher.extension@1.2.3")
        self.assertIn("pkg:npm/lodash@4.17.21", sbom["dependencies"][0]["dependsOn"])

    def test_does_not_claim_a_missing_or_invalid_artifact_hash(self) -> None:
        sbom = build_cyclonedx_sbom({"summary": {}, "extensions": [{"extension_id": "publisher.extension", "version": "1.2.3", "artifact_sha256": "not-a-hash", "dependencies": {}}]})
        extension = next(item for item in sbom["components"] if item["type"] == "application")
        self.assertNotIn("hashes", extension)
