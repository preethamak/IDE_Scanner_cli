from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Iterator


MAX_SNAPSHOT_FILES = 100_000
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024 * 1024


@contextmanager
def snapshot_installations(rows: list[dict[str, Any]]) -> Iterator[list[dict[str, Any]]]:
    """Create stable, private copies of installed extensions before analysis."""
    with tempfile.TemporaryDirectory(prefix="guardrails-scan-") as directory:
        root = Path(directory)
        snapshots: list[dict[str, Any]] = []
        for index, row in enumerate(rows):
            source = Path(str(row["path"])).resolve()
            before = _manifest(source)
            destination = root / f"installation-{index + 1}"
            _copy_manifest(source, destination, before)
            after = _manifest(source)
            if before != after:
                raise ValueError(f"Installed extension changed while it was being copied: {row['extension_id']}")
            snapshots.append({**row, "path": str(destination), "original_path": str(source)})
        yield snapshots


def _manifest(root: Path) -> dict[str, tuple[int, int]]:
    if not root.is_dir():
        raise ValueError(f"Installed extension path is not a directory: {root}")
    manifest: dict[str, tuple[int, int]] = {}
    total_bytes = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *files]:
            candidate = current_path / name
            if candidate.is_symlink():
                raise ValueError(f"Installed extension contains a symbolic link that cannot be snapshotted safely: {candidate.relative_to(root)}")
        for name in files:
            candidate = current_path / name
            try:
                stat = candidate.stat(follow_symlinks=False)
            except OSError as exc:
                raise ValueError(f"Could not read installed extension file: {candidate.relative_to(root)}") from exc
            relative = candidate.relative_to(root).as_posix()
            manifest[relative] = (stat.st_size, stat.st_mtime_ns)
            total_bytes += stat.st_size
            if len(manifest) > MAX_SNAPSHOT_FILES:
                raise ValueError(f"Installed extension exceeds the {MAX_SNAPSHOT_FILES:,}-file snapshot limit: {root.name}")
            if total_bytes > MAX_SNAPSHOT_BYTES:
                raise ValueError("Installed extension exceeds the 2 GiB snapshot limit.")
    return manifest


def _copy_manifest(source: Path, destination: Path, manifest: dict[str, tuple[int, int]]) -> None:
    destination.mkdir(mode=0o700, parents=True)
    for relative in manifest:
        source_file = source / relative
        destination_file = destination / relative
        destination_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source_file, destination_file, follow_symlinks=False)
        try:
            destination_file.chmod(0o600)
        except OSError:
            pass
