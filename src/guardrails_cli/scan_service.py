from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from .scanner_adapter import DEEP_REQUIRED_PROVIDERS, display_report, scan_paths
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
            lambda required_providers: scan_paths(
                [row["path"] for row in snapshot_rows],
                online=online or profile == "deep",
                required_providers=required_providers,
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


def run_with_profile(
    profile: str,
    operation: Callable[[frozenset[str]], dict[str, Any]],
) -> dict[str, Any]:
    required_providers = DEEP_REQUIRED_PROVIDERS if profile == "deep" else frozenset()
    return operation(required_providers)
