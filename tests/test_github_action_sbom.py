from __future__ import annotations

import unittest
from pathlib import Path


class GithubActionSbomTests(unittest.TestCase):
    def test_action_generates_and_retains_an_sbom_without_changing_the_gate(self) -> None:
        action = (Path(__file__).resolve().parents[1] / "action.yml").read_text(encoding="utf-8")
        self.assertIn("sbom-path:", action)
        self.assertIn("upload-sbom:", action)
        self.assertIn("guardrails report sbom", action)
        self.assertIn("guardrails-extension-sbom", action)
        self.assertIn("Enforce GuardRails outcome", action)
