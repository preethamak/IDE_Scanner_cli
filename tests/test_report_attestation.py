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
