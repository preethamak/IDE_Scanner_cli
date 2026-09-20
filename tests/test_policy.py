from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from guardrails_cli.policy import check_installed_extensions, compute_policy_hash, load_policy_bundle, verify_artifact


class PolicyTests(unittest.TestCase):
    def bundle(self) -> dict[str, object]:
        bundle = {
            "schema": "guardrails.enterprise-policy.v1",
            "default_action": "deny",
            "enforcement": {
                "vscode": {"settings": {"extensions.allowed": {"*": False}, "extensions.autoUpdate": False}},
                "guardrails": {
                    "requires_artifact_sha256": True,
                    "requires_complete_analysis": True,
                    "requires_capability_contract": True,
                    "exact_release_allowlist": [],
                },
            },
            "entries": [{
                "extension_id": "publisher.extension",
                "version": "1.2.3",
                "decision": "allow",
                "artifact_sha256": "b" * 64,
                "analysis_status": "complete",
                "capability_contract": {
                    "observed": ["agent_shell"],
                    "requires_explicit_review": True,
                    "review_reason": "high-impact capability",
                },
            }],
        }
        bundle["enforcement"]["guardrails"]["exact_release_allowlist"] = bundle["entries"]  # type: ignore[index]
        bundle["enforcement"]["vscode"]["settings"]["extensions.allowed"] = {  # type: ignore[index]
            "*": False,
            "publisher.extension": ["1.2.3"],
        }
        bundle["policy_hash"] = compute_policy_hash(bundle)
        return bundle

    def test_exact_version_is_allowed_and_unknown_version_is_blocked(self) -> None:
        result = check_installed_extensions(self.bundle(), [
            {"extension_id": "publisher.extension", "version": "1.2.3", "client": "VS Code"},
            {"extension_id": "publisher.extension", "version": "1.2.4", "client": "VS Code"},
        ])
        self.assertEqual(result["summary"], {"installed": 2, "allowed": 1, "blocked": 1, "unverified": 1, "compliant": False})
        self.assertEqual(result["results"][0]["status"], "version_allowed_unverified")
        self.assertEqual(result["results"][0]["hash_verification"], "required_not_available_for_installed_directory")
        self.assertTrue(result["results"][0]["capability_contract"]["requires_explicit_review"])
        self.assertEqual(result["results"][1]["status"], "blocked")

    def test_bundle_loader_rejects_non_guardrails_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps({"schema": "other"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_policy_bundle(path)

    def test_bundle_loader_rejects_changed_contents(self) -> None:
        bundle = self.bundle()
        bundle["entries"][0]["version"] = "1.2.4"  # type: ignore[index]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "integrity check"):
                load_policy_bundle(path)

    def test_bundle_loader_rejects_self_consistent_incomplete_release(self) -> None:
        bundle = self.bundle()
        bundle["entries"][0]["analysis_status"] = "incomplete"  # type: ignore[index]
        bundle["policy_hash"] = compute_policy_hash(bundle)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "complete analysis"):
                load_policy_bundle(path)

    def test_bundle_loader_rejects_self_consistent_invalid_artifact_hash(self) -> None:
        bundle = self.bundle()
        bundle["entries"][0]["artifact_sha256"] = "not-a-hash"  # type: ignore[index]
        bundle["policy_hash"] = compute_policy_hash(bundle)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                load_policy_bundle(path)

    def test_bundle_loader_rejects_tampered_enforcement_defaults(self) -> None:
        bundle = self.bundle()
        bundle["enforcement"]["vscode"]["settings"]["extensions.allowed"]["*"] = True  # type: ignore[index]
        bundle["policy_hash"] = compute_policy_hash(bundle)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "deny unknown extensions"):
                load_policy_bundle(path)

    def test_bundle_loader_rejects_divergent_exact_allowlists(self) -> None:
        bundle = self.bundle()
        bundle["enforcement"]["vscode"]["settings"]["extensions.allowed"]["publisher.extension"] = ["9.9.9"]  # type: ignore[index]
        bundle["policy_hash"] = compute_policy_hash(bundle)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "VS Code allowlist"):
                load_policy_bundle(path)

    def test_bundle_loader_rejects_duplicate_exact_releases(self) -> None:
        bundle = self.bundle()
        bundle["entries"].append(dict(bundle["entries"][0]))  # type: ignore[index]
        bundle["enforcement"]["guardrails"]["exact_release_allowlist"] = bundle["entries"]  # type: ignore[index]
        bundle["policy_hash"] = compute_policy_hash(bundle)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate exact release"):
                load_policy_bundle(path)

    def test_published_artifact_hash_must_match_an_approved_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "extension.vsix"
            artifact.write_bytes(b"exact-published-bytes")
            bundle = {
                "schema": "guardrails.enterprise-policy.v1",
                "team_id": "team-1",
                "default_action": "deny",
                "entries": [{
                    "extension_id": "publisher.extension",
                    "version": "1.2.3",
                    "decision": "allow",
                    "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }],
                "unresolved": [],
            }
            bundle["policy_hash"] = compute_policy_hash(bundle)
            result = verify_artifact(bundle, artifact)
            self.assertEqual(result["status"], "allowed")
            self.assertEqual(result["matched_releases"][0]["version"], "1.2.3")
