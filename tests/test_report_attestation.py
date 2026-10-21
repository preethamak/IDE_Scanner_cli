from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from guardrails_cli.report_attestation import create_attestation, verify_attestation


class ReportAttestationTests(unittest.TestCase):
    def test_attestation_binds_exact_report_bytes_without_claiming_a_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"; report.write_text(json.dumps({"summary": {}, "extensions": [], "metadata": {"scan_id": "scan-1"}}), encoding="utf-8")
            attestation = create_attestation(report); assertion = Path(directory) / "report.attestation.json"; assertion.write_text(json.dumps(attestation), encoding="utf-8")
            self.assertIsNone(attestation["signature"]); self.assertIn("not signer identity", attestation["note"]); self.assertEqual(verify_attestation(report, assertion)[0], True)
            report.write_text("{}", encoding="utf-8"); self.assertEqual(verify_attestation(report, assertion)[0], False)

    def test_attestation_verification_enforces_report_claims_for_ci(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text(
                json.dumps(
                    {
                        "summary": {},
                        "extensions": [],
                        "metadata": {
                            "scan_id": "scan-42",
                            "scanner_build": "build-2026.10.21",
                            "ruleset_version": "2026.10",
                        },
                    }
                ),
                encoding="utf-8",
            )
            assertion = Path(directory) / "report.attestation.json"
            assertion.write_text(json.dumps(create_attestation(report)), encoding="utf-8")

            self.assertTrue(
                verify_attestation(
                    report,
                    assertion,
                    required_claims={
                        "scan_id": "scan-42",
                        "scanner_build": "build-2026.10.21",
                        "ruleset_version": "2026.10",
                    },
                )[0]
            )
            self.assertFalse(
                verify_attestation(report, assertion, required_claims={"ruleset_version": "old"})[0]
            )

    def test_attestation_rejects_tampered_metadata_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text(json.dumps({"summary": {}, "extensions": [], "metadata": {"scan_id": "scan-1"}}), encoding="utf-8")
            assertion = create_attestation(report)
            assertion["report"]["scan_id"] = "scan-other"
            assertion_path = Path(directory) / "report.attestation.json"
            assertion_path.write_text(json.dumps(assertion), encoding="utf-8")
            ok, message = verify_attestation(report, assertion_path)
            self.assertFalse(ok)
            self.assertIn("scan_id", message)
