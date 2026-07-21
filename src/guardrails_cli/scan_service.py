from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .scanner_adapter import display_report, scan_paths
from .snapshot import snapshot_installations


ProgressCallback = Callable[[str], None]


def scan_installed(
    rows: list[dict[str, Any]],
    *,
    profile: str = "standard",
    online: bool = False,
    progress: ProgressCallback | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Scan selected installations and return raw and presentation reports."""
    if not rows:
        raise ValueError("Select at least one installed extension before scanning.")
    update = progress or (lambda _message: None)
    update(f"Creating private snapshots for {len(rows)} installation(s)…")
    with snapshot_installations(rows) as snapshot_rows:
        update("Analyzing extension packages without executing their code…")
        report = run_with_profile(
            profile,
            lambda: scan_paths(
                [row["path"] for row in snapshot_rows],
                online=online or profile == "deep",
            ),
        )
        attach_installation_context(report, snapshot_rows)
    update("Preparing the local security report…")
    return report, display_report(report, source="installed", profile=profile)


def attach_installation_context(report: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    by_path = {str(Path(row["path"]).resolve()): row for row in rows}
    for extension in report.get("extensions", []):
        if not isinstance(extension, dict):
            continue
        install_path = str(extension.get("install_path") or "")
        try:
            context = by_path.get(str(Path(install_path).resolve()))
        except OSError:
            context = None
        if context:
            extension["client"] = context["client"]
            extension["installation_path"] = context.get("original_path") or context["path"]


def run_with_profile(profile: str, operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    previous = os.environ.get("IDE_SCANNER_REQUIRE_PROVIDERS")
    if profile == "deep":
        existing = {item.strip() for item in (previous or "").split(",") if item.strip()}
        existing.update({"semgrep", "yara", "dependency_intelligence"})
        os.environ["IDE_SCANNER_REQUIRE_PROVIDERS"] = ",".join(sorted(existing))
    try:
        return operation()
    finally:
        if previous is None:
            os.environ.pop("IDE_SCANNER_REQUIRE_PROVIDERS", None)
        else:
            os.environ["IDE_SCANNER_REQUIRE_PROVIDERS"] = previous
