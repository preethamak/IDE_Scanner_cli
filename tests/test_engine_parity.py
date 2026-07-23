from __future__ import annotations

import json
import shutil
import tempfile
import unittest
import zipfile
from importlib.resources import files
from pathlib import Path

from guardrails_cli.scanner_adapter import engine_identity, scan_paths, verify_engine_integrity, write_bundle
from ide_scanner.classification_policy import POLICY_VERSION
from ide_scanner.rule_registry import rules_json


class EngineParityTests(unittest.TestCase):
    def test_vendored_engine_matches_its_source_manifest(self) -> None:
        from scripts.sync_vendored_engine import check

        check()
        source = json.loads(files("guardrails_cli").joinpath("engine_source.json").read_text(encoding="utf-8"))
        self.assertEqual(engine_identity()["build"], source["source_revision"])

    def test_runtime_integrity_check_rejects_overwritten_engine_files(self) -> None:
        source_root = Path(__file__).parents[1] / "src" / "ide_scanner"
        with tempfile.TemporaryDirectory() as directory:
            copied_root = Path(directory) / "ide_scanner"
            shutil.copytree(source_root, copied_root)
            with (copied_root / "scanner.py").open("a", encoding="utf-8") as handle:
                handle.write("\n# unexpected overwrite\n")
            with self.assertRaisesRegex(RuntimeError, "integrity check failed"):
                verify_engine_integrity(copied_root)

    def test_cli_bundle_preserves_canonical_engine_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(
                json.dumps({
                    "publisher": "parity",
                    "name": "fixture",
                    "version": "1.0.0",
                    "main": "extension.js",
                    "activationEvents": ["onCommand:parity.run"],
                }),
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "exports.activate = function () { return undefined; };",
                encoding="utf-8",
            )
            report = scan_paths([root], online=False)
            output = root / "report.zip"
            write_bundle(report, output, source="fixture", profile="standard")

            with zipfile.ZipFile(output) as archive:
                metadata = json.loads(archive.read("metadata.json"))
                leaderboard = json.loads(archive.read("leaderboard.json"))
                detail = json.loads(archive.read(leaderboard["extensions"][0]["detail_ref"]))

        raw = report["extensions"][0]
        for field in (
            "analysis_status",
            "decision",
            "severity",
            "risk_score",
            "malware_score",
            "score_schema_version",
        ):
            self.assertEqual(detail[field], raw[field], msg=f"CLI changed canonical {field}")

        raw_findings = {item["finding_id"]: item for item in raw["findings"]}
        bundled_findings = {item["finding_id"]: item for item in detail["findings"]}
        self.assertEqual(raw_findings.keys(), bundled_findings.keys())
        for finding_id in raw_findings:
            for field in ("rule_id", "evidence_class", "actionability", "effective_severity"):
                self.assertEqual(
                    bundled_findings[finding_id][field],
                    raw_findings[finding_id][field],
                    msg=f"CLI changed {field} for {finding_id}",
                )

        catalog = rules_json()
        self.assertEqual(metadata["scanner_build"], engine_identity()["build"])
        self.assertEqual(metadata["ruleset_version"], report["ruleset_version"])
        self.assertEqual(metadata["policy_version"], POLICY_VERSION)
        self.assertEqual(metadata["ruleset_version"], catalog["ruleset_version"])
        self.assertEqual(metadata["policy_version"], catalog["policy_version"])


if __name__ == "__main__":
    unittest.main()
