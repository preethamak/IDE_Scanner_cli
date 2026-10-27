import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from guardrails_cli.policy import check_capability_policy, load_capability_policy_bundle, verify_artifact


class FailClosedPolicyTests(unittest.TestCase):
    def test_invalid_evaluations_cannot_become_compliant(self):
        cases = [None, [None], [{"subject_id": "x", "outcome": "unexpected", "requests": []}],
                 [{"subject_id": "x", "outcome": "allow", "requests": []}],
                 [{"subject_id": "x", "outcome": "allow", "requests": [{"decision": "deny"}]}]]
        for evaluations in cases:
            with self.subTest(evaluations=evaluations), self.assertRaises(ValueError):
                check_capability_policy({"evaluations": evaluations})

    def test_self_consistent_hash_does_not_authorize_unknown_outcomes(self):
        payload = {"schema": "guardrails.capability-policy.v1", "default_action": "deny",
                   "evaluations": [{"subject_id": "x", "outcome": "unexpected", "requests": []}]}
        payload["policy_hash"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(payload))
            with self.assertRaises(ValueError):
                load_capability_policy_bundle(path)

    def test_scanned_child_requires_its_own_exact_release_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "parent.vsix"
            artifact.write_bytes(b"parent artifact")
            parent = {"extension_id": "vendor.parent", "version": "1", "decision": "allow",
                      "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "analysis_status": "complete",
                      "relationship_contract": {"requires_separate_review": False, "declared": [{
                          "extension_id": "vendor.child", "relationship": "extension_dependency", "status": "scanned",
                          "resolved_version": "2", "resolved_artifact_sha256": "a" * 64}]}}
            child = {"extension_id": "vendor.child", "version": "2", "artifact_sha256": "a" * 64,
                     "analysis_status": "complete", "decision": "block"}
            bundle = {"entries": [parent, child]}
            self.assertEqual(verify_artifact(bundle, artifact)["status"], "relationship_review_required")
            child["decision"] = "allow"
            self.assertEqual(verify_artifact(bundle, artifact)["status"], "allowed")
            child["artifact_sha256"] = "b" * 64
            self.assertEqual(verify_artifact(bundle, artifact)["status"], "relationship_review_required")
