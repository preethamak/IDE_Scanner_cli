from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from guardrails_cli import main as cli
from guardrails_cli.risk_brief import build_risk_brief
from guardrails_cli.ui.prompts import prompt_choice
from guardrails_cli.environment import doctor_checks


class GuardrailsCliTests(unittest.TestCase):
    def run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_version_uses_guardrails_brand(self) -> None:
        code, output, error = self.run_cli(["version"])
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.assertIn("Guardrails 0.2.3", output)

    def test_doctor_reports_dynamic_sandbox_readiness(self) -> None:
        with (
            patch("guardrails_cli.environment.installed_extensions", return_value=[]),
            patch("guardrails_cli.environment.analysis_provider_diagnostics", return_value={
                "semgrep": {"status": "available", "executable": "semgrep", "ruleset_hash": "a" * 64},
                "yara": {"status": "available", "executable": "yara", "ruleset_hash": "b" * 64},
            }),
            patch("guardrails_cli.environment.engine_identity", return_value={"version": "1.0.0", "build": "c" * 40}),
            patch("guardrails_cli.environment.rules_json", return_value={"ruleset_version": "rules-test", "rules": [{"rule_id": "example"}]}),
            patch("guardrails_cli.environment.sandbox_preflight", return_value={
                "status": "unavailable", "error": "namespace permission denied",
            }),
        ):
            checks = doctor_checks()

        self.assertIn(("Dynamic sandbox", "FAIL", "namespace permission denied"), checks)
        self.assertIn(("Scanner", "OK", "engine 1.0.0 · build cccccccccccc · rules rules-test (1)"), checks)

    def test_standard_version_flag_is_supported(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            cli.main(["--version"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("Guardrails 0.2.3", output.getvalue())

    def test_help_manual_explains_commands_and_shortcuts(self) -> None:
        code, output, error = self.run_cli(["help"])
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.assertIn("Command map", output)
        self.assertIn("guardrails help shortcuts", output)

        code, output, error = self.run_cli(["help", "scan"])
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.assertIn("local, uploaded, and installed-extension inputs", output)

        code, output, error = self.run_cli(["help", "automation"])
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.assertIn("Exit codes", output)

    def test_noninteractive_installed_scan_requires_selection(self) -> None:
        rows = [{"client": "VS Code", "path": "/tmp/ext", "extension_id": "one.ext", "display_name": "One", "publisher": "one", "version": "1.0.0"}]
        with patch("guardrails_cli.main.installed_extensions", return_value=rows), patch("guardrails_cli.main.sys.stdin.isatty", return_value=False):
            code, _output, error = self.run_cli(["scan"])
        self.assertEqual(code, 2)
        self.assertIn("--all, --extension, or --select", error)

    def test_inventory_export_matches_team_workspace_contract_without_paths(self) -> None:
        rows = [
            {"client": "Cursor", "path": "/private/extensions/one", "extension_id": "sample.one", "display_name": "One", "publisher": "sample", "version": "1.0.0"},
            {"client": "VS Code", "path": "/private/extensions/two", "extension_id": "sample.two", "display_name": "Two", "publisher": "sample", "version": "2.0.0"},
        ]
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("guardrails_cli.main.installed_extensions", return_value=rows),
            patch("guardrails_cli.main.platform.system", return_value="Linux"),
        ):
            output = Path(directory) / "inventory.json"
            code, message, error = self.run_cli(["inventory", "--ide", "cursor", "--device-id", "team-laptop-1", "--device-name", "Team laptop", "--output", str(output)])
            payload = __import__("json").loads(output.read_text(encoding="utf-8"))
        self.assertEqual((code, error), (0, ""))
        self.assertIn("Exported 1 installed extensions", message)
        self.assertEqual(payload["device"], {"id": "team-laptop-1", "name": "Team laptop", "platform": "linux"})
        self.assertEqual(payload["source"], "cli")
        self.assertEqual(payload["extensions"], [{"extension_id": "sample.one", "version": "1.0.0", "registry": "unknown"}])
        self.assertNotIn("/private", str(payload))

    def test_inventory_export_rejects_unsafe_device_identifiers(self) -> None:
        rows = [{"client": "Cursor", "extension_id": "sample.one", "version": "1.0.0"}]
        with patch("guardrails_cli.main.installed_extensions", return_value=rows):
            code, _message, error = self.run_cli(["inventory", "--ide", "cursor", "--device-id", "../../host", "--output", "ignored.json"])
        self.assertEqual(code, 2)
        self.assertIn("Device id", error)

    def test_tui_requires_an_interactive_terminal(self) -> None:
        code, _output, error = self.run_cli(["tui"])
        self.assertEqual(code, 2)
        self.assertIn("requires a terminal", error)

    def test_missing_report_is_a_product_error_not_a_traceback(self) -> None:
        code, _output, error = self.run_cli(["report", "view", "/tmp/guardrails-missing-report.zip"])
        self.assertEqual(code, 2)
        self.assertIn("Report does not exist", error)
        self.assertNotIn("Traceback", error)

    def test_invalid_offline_online_combination_is_rejected(self) -> None:
        code, _output, error = self.run_cli(["scan", "--all", "--profile", "offline", "--online"])
        self.assertEqual(code, 2)
        self.assertIn("cannot be combined", error)

    def test_marketplace_scan_forwards_registry_snapshot(self) -> None:
        report = {"scan_id": "scan-1", "summary": {}, "extensions": []}
        with (
            patch("guardrails_cli.main.scan_marketplace", return_value=report) as scan,
            patch("guardrails_cli.main.display_report", return_value=report),
            patch("guardrails_cli.main.render_scan_report", return_value="ok"),
        ):
            code, output, error = self.run_cli([
                "scan",
                "--marketplace",
                "sample.extension@1.0.0",
                "--profile",
                "deep",
                "--target-platform",
                "darwin-x64",
                "--registry-snapshot",
                "prior-report.json",
                "--fail-on",
                "never",
            ])

        self.assertEqual((code, error), (0, ""))
        scan.assert_called_once_with(
            "sample.extension",
            version="1.0.0",
            target_platform="darwin-x64",
            extension_advisories=None,
            registry_snapshot="prior-report.json",
            required_providers=frozenset({"semgrep", "yara", "dependency_intelligence"}),
            dynamic_runtime=True,
            runtime_timeout_seconds=20,
        )

    def test_marketplace_scan_forwards_exact_advisory_snapshot(self) -> None:
        report = {"scan_id": "scan-1", "summary": {}, "extensions": []}
        with (
            patch("guardrails_cli.main.scan_marketplace", return_value=report) as scan,
            patch("guardrails_cli.main.display_report", return_value=report),
            patch("guardrails_cli.main.render_scan_report", return_value="ok"),
        ):
            code, _output, error = self.run_cli([
                "scan", "--marketplace", "sample.extension@1.0.0",
                "--extension-advisories", "advisories.json", "--fail-on", "never",
            ])

        self.assertEqual((code, error), (0, ""))
        self.assertEqual(scan.call_args.kwargs["extension_advisories"], "advisories.json")

    def test_local_deep_scan_forwards_runtime_contract(self) -> None:
        report = {"scan_id": "scan-1", "summary": {}, "extensions": []}
        with (
            patch("guardrails_cli.main.discover_paths", return_value=[{"type": "vsix", "path": "/tmp/sample.vsix"}]),
            patch("guardrails_cli.main.scan_paths", return_value=report) as scan,
            patch("guardrails_cli.main.display_report", return_value=report),
            patch("guardrails_cli.main.render_scan_report", return_value="ok"),
        ):
            code, output, error = self.run_cli([
                "scan",
                "--file",
                "/tmp/sample.vsix",
                "--profile",
                "deep",
                "--runtime-timeout",
                "37",
                "--format",
                "terminal",
                "--fail-on",
                "never",
            ])

        self.assertEqual((code, error), (0, ""))
        self.assertIn("capability-gated Bubblewrap runtime", output)
        scan.assert_called_once_with(
            ["/tmp/sample.vsix"],
            online=True,
            extension_advisories=None,
            registry_snapshot=None,
            required_providers=frozenset({"semgrep", "yara", "dependency_intelligence"}),
            dynamic_runtime=True,
            runtime_timeout_seconds=37,
        )

    def test_brief_scans_each_exact_candidate_and_fails_closed_for_review(self) -> None:
        clean = {
            "extensions": [{
                "extension_id": "sample.clean", "version": "1.0.0", "publisher": "sample",
                "decision": "allow", "decision_reason": "No decision-level evidence.",
                "risk_score": 0, "malware_score": 0,
                "analysis_coverage": {
                    "status": "complete", "coverage_percent": 100,
                    "providers": {"dependency_intelligence": {"status": "completed"}},
                },
                "artifact_identity": {"sha256": "a" * 64},
                "provenance": {"tier": "verified", "publisher_verified": True, "artifact_identity_consistent": True},
                "findings": [],
            }],
        }
        review = {
            "extensions": [{
                "extension_id": "sample.review", "version": "2.0.0", "publisher": "sample",
                "decision": "review", "decision_reason": "Requires context.",
                "risk_score": 45, "malware_score": 0,
                "analysis_coverage": {
                    "status": "complete", "coverage_percent": 100,
                    "providers": {"dependency_intelligence": {"status": "completed"}},
                },
                "artifact_identity": {"sha256": "b" * 64},
                "provenance": {"tier": "unknown", "publisher_verified": False, "artifact_identity_consistent": True},
                "findings": [{"rule_id": "process-execution", "actionability": "review"}],
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "brief.json"
            with patch("guardrails_cli.main.scan_marketplace", side_effect=[clean, review]) as scan:
                code, _message, error = self.run_cli([
                    "brief", "--purpose", "read plist files",
                    "--marketplace", "sample.clean@1.0.0",
                    "--marketplace", "sample.review@2.0.0",
                    "--format", "json", "--output", str(output),
                ])
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual((code, error), (1, ""))
        self.assertEqual(scan.call_count, 2)
        self.assertEqual(payload["comparison"]["eligible_candidates"], ["sample.clean"])
        gates = {candidate["extension_id"]: candidate["recommendation_gate"]["status"] for candidate in payload["candidates"]}
        self.assertEqual(gates, {"sample.clean": "eligible_for_recommendation", "sample.review": "needs_human_review"})
        handoffs = {candidate["extension_id"]: candidate["agent_handoff"] for candidate in payload["candidates"]}
        self.assertEqual(handoffs["sample.clean"]["recommendation_permitted"], True)
        self.assertEqual(handoffs["sample.review"]["recommendation_permitted"], False)
        self.assertFalse(handoffs["sample.clean"]["installation_permitted"])
        self.assertFalse(payload["agent_handoff"]["recommendation_permitted"])
        self.assertFalse(payload["agent_handoff"]["installation_permitted"])
        self.assertIn("Do not recommend", payload["agent_policy"][0])

    def test_deep_brief_forwards_runtime_contract(self) -> None:
        report = {
            "extensions": [{
                "extension_id": "sample.deep", "version": "1.0.0", "publisher": "sample",
                "decision": "incomplete", "analysis_coverage": {"status": "incomplete", "coverage_percent": 0},
                "artifact_identity": {"sha256": "a" * 64}, "findings": [],
            }],
        }
        with patch("guardrails_cli.main.scan_marketplace", return_value=report) as scan:
            code, _output, error = self.run_cli([
                "brief", "--purpose", "read plist files", "--profile", "deep",
                "--marketplace", "sample.deep@1.0.0",
            ])

        self.assertEqual((code, error), (3, ""))
        scan.assert_called_once_with(
            "sample.deep",
            version="1.0.0",
            target_platform=None,
            extension_advisories=None,
            registry_snapshot=None,
            required_providers=frozenset({"semgrep", "yara", "dependency_intelligence"}),
            dynamic_runtime=True,
        )

    def test_brief_never_treats_incomplete_analysis_as_recommendable(self) -> None:
        incomplete = {
            "extensions": [{
                "extension_id": "sample.incomplete", "version": "1.0.0", "publisher": "sample",
                "decision": "incomplete", "analysis_coverage": {"status": "incomplete", "coverage_percent": 72},
                "artifact_identity": {"sha256": ""}, "findings": [],
            }],
        }
        with patch("guardrails_cli.main.scan_marketplace", return_value=incomplete):
            code, output, error = self.run_cli([
                "brief", "--purpose", "read plist files", "--marketplace", "sample.incomplete",
            ])
        self.assertEqual((code, error), (3, ""))
        self.assertIn("insufficient_evidence", output)

    def test_brief_exposes_raw_maintenance_and_advisory_signals(self) -> None:
        report = {
            "extensions": [{
                "extension_id": "sample.maintained", "version": "1.0.0", "publisher": "sample",
                "decision": "allow", "analysis_coverage": {
                    "status": "complete", "coverage_percent": 100,
                    "providers": {"dependency_intelligence": {"status": "completed"}},
                },
                "artifact_identity": {"sha256": "a" * 64},
                "findings": [
                    {
                        "rule_id": "marketplace-verified-publisher", "evidence_class": "reputation",
                        "evidence": {
                            "evidence_class": "reputation", "registry": "vs-marketplace", "install_count": 1200,
                            "rating_average": 4.7, "rating_count": 42, "last_updated": "2026-08-01T00:00:00Z",
                        },
                    },
                    {
                        "rule_id": "repo-maintained", "evidence_class": "reputation",
                        "evidence": {
                            "evidence_class": "reputation", "host": "github", "full_name": "sample/maintained",
                            "stargazers_count": 321, "pushed_at": "2026-08-02T00:00:00Z", "archived": False, "fork": False,
                        },
                    },
                ],
            }],
        }
        brief = build_risk_brief([report], purpose="read plist files", profile="standard")
        candidate = brief["candidates"][0]
        self.assertEqual(candidate["reputation_signals"]["marketplace"]["install_count"], 1200)
        self.assertEqual(candidate["reputation_signals"]["repository"]["full_name"], "sample/maintained")
        self.assertEqual(candidate["dependency_advisory"], {
            "coverage_status": "completed", "status": "no_osv_findings_observed", "finding_rules": [],
        })

    def test_brief_requires_review_when_osv_or_maintenance_findings_exist(self) -> None:
        report = {
            "extensions": [{
                "extension_id": "sample.stale", "version": "1.0.0", "publisher": "sample",
                "decision": "allow", "analysis_coverage": {
                    "status": "complete", "coverage_percent": 100,
                    "providers": {"dependency_intelligence": {"status": "completed"}},
                },
                "artifact_identity": {"sha256": "a" * 64},
                "findings": [{
                    "rule_id": "vulnerable-npm-dependency", "evidence_class": "dependency",
                    "evidence": {"evidence_class": "dependency"},
                }],
            }],
        }
        candidate = build_risk_brief([report], purpose="read plist files", profile="standard")["candidates"][0]
        self.assertEqual(candidate["recommendation_gate"]["status"], "needs_human_review")
        self.assertIn("Dependency advisory findings", candidate["recommendation_gate"]["reason"])

    def test_installed_search_filters_before_selection(self) -> None:
        rows = [
            {"client": "VS Code", "path": "/tmp/one", "extension_id": "sample.one", "display_name": "Alpha", "publisher": "sample", "version": "1.0.0"},
            {"client": "Cursor", "path": "/tmp/two", "extension_id": "sample.two", "display_name": "Solidity Tools", "publisher": "sample", "version": "2.0.0"},
        ]
        args = cli._scan_namespace(search="solidity", all=True)
        with patch("guardrails_cli.main.installed_extensions", return_value=rows), redirect_stdout(io.StringIO()):
            selected = cli._select_installed(args)
        self.assertEqual([item["extension_id"] for item in selected], ["sample.two"])

    def test_picker_is_bounded_and_searchable_for_large_inventories(self) -> None:
        rows = [
            {"client": "VS Code", "path": f"/tmp/{index}", "extension_id": f"sample.ext-{index}", "display_name": f"Extension {index}", "publisher": "sample", "version": "1.0.0"}
            for index in range(100)
        ]
        rows[73]["display_name"] = "Solidity Tools"
        output = io.StringIO()
        with patch("builtins.input", side_effect=["/solidity", "1", "d"]), redirect_stdout(output):
            selected = cli._interactive_installed_picker(rows)
        self.assertEqual([item["extension_id"] for item in selected], ["sample.ext-73"])
        self.assertIn("100 detected", output.getvalue())
        self.assertIn("1 match", output.getvalue())
        self.assertNotIn("Extension 99", output.getvalue())

    def test_fail_on_policy_has_stable_exit_codes(self) -> None:
        block = {"extensions": [{"decision": "block"}]}
        review = {"extensions": [{"decision": "review"}]}
        incomplete = {"extensions": [{"decision": "incomplete"}]}
        self.assertEqual(cli._scan_exit_code(block, "block"), 1)
        self.assertEqual(cli._scan_exit_code(review, "block"), 0)
        self.assertEqual(cli._scan_exit_code(review, "review"), 1)
        self.assertEqual(cli._scan_exit_code(incomplete, "never"), 3)

    def test_export_menu_prints_numbered_formats_before_prompting(self) -> None:
        choices = ["HTML — readable report (recommended)", "ZIP — verifiable evidence bundle", "Skip export"]
        output = io.StringIO()
        with patch("builtins.input", return_value="2"), redirect_stdout(output):
            selected = prompt_choice("Choose export format", choices)
        self.assertEqual(selected, 1)
        self.assertIn("1  HTML", output.getvalue())
        self.assertIn("2  ZIP", output.getvalue())
        self.assertIn("3  Skip", output.getvalue())

    def test_fresh_html_export_builds_its_presentation_model(self) -> None:
        report = {"scan_id": "scan-1", "summary": {}, "extensions": []}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            cli._export_fresh(report, "html", str(output), source="installed", profile="standard")
            content = output.read_text(encoding="utf-8")
        self.assertIn("Guardrails", content)


if __name__ == "__main__":
    unittest.main()
