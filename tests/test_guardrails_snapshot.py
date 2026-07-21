from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from guardrails_cli.snapshot import snapshot_installations


class GuardrailsSnapshotTests(unittest.TestCase):
    def test_snapshot_is_private_and_removed_after_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "extension"
            source.mkdir()
            (source / "package.json").write_text('{"name":"sample"}', encoding="utf-8")
            row = {"path": str(source), "extension_id": "sample.extension"}
            with snapshot_installations([row]) as snapshots:
                snapshot = Path(snapshots[0]["path"])
                self.assertTrue((snapshot / "package.json").exists())
                self.assertEqual(snapshots[0]["original_path"], str(source.resolve()))
            self.assertFalse(snapshot.exists())


if __name__ == "__main__":
    unittest.main()
