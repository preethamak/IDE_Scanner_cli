"""Stable inputs shared by the CLI, worker, and scanner orchestration layers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScanRequest:
    """Immutable normalized request for one canonical scanner run."""

    paths: tuple[Path | str, ...] = ()
    extension_ids: tuple[str, ...] = ()
    marketplace_scan_ids: tuple[str, ...] = ()
    marketplace_version: str | None = None
    marketplace_target_platform: str | None = None
    include_fixtures: bool = False
    all_local: bool = False
    online: bool = False
    known_bad_hashes_file: Path | str | None = None
    threat_feed_file: Path | str | None = None
    extension_advisories_file: Path | str | None = None
    registry_snapshot_file: Path | str | None = None
    sandbox_observations_file: Path | str | None = None
    previous_report_file: Path | str | None = None
    path_artifact_origin: str | None = None
    artifact_url: str | None = None
    artifact_sha256: str | None = None
    dynamic_runtime: bool = False
    runtime_timeout_seconds: int = 15
    include_posture: bool = True
    required_providers: frozenset[str] = frozenset()

    @classmethod
    def create(
        cls,
        *,
        paths: list[Path | str] | None = None,
        extension_ids: list[str] | None = None,
        marketplace_scan_ids: list[str] | None = None,
        marketplace_version: str | None = None,
        marketplace_target_platform: str | None = None,
        include_fixtures: bool = False,
        all_local: bool = False,
        online: bool = False,
        known_bad_hashes_file: Path | str | None = None,
        threat_feed_file: Path | str | None = None,
        extension_advisories_file: Path | str | None = None,
        registry_snapshot_file: Path | str | None = None,
        sandbox_observations_file: Path | str | None = None,
        previous_report_file: Path | str | None = None,
        path_artifact_origin: str | None = None,
        artifact_url: str | None = None,
        artifact_sha256: str | None = None,
        dynamic_runtime: bool = False,
        runtime_timeout_seconds: int = 15,
        include_posture: bool = True,
        required_providers: set[str] | frozenset[str] | None = None,
    ) -> "ScanRequest":
        return cls(
            paths=tuple(paths or ()),
            extension_ids=tuple(extension_ids or ()),
            marketplace_scan_ids=tuple(marketplace_scan_ids or ()),
            marketplace_version=marketplace_version,
            marketplace_target_platform=marketplace_target_platform,
            include_fixtures=include_fixtures,
            all_local=all_local,
            online=online,
            known_bad_hashes_file=known_bad_hashes_file,
            threat_feed_file=threat_feed_file,
            extension_advisories_file=extension_advisories_file,
            registry_snapshot_file=registry_snapshot_file,
            sandbox_observations_file=sandbox_observations_file,
            previous_report_file=previous_report_file,
            path_artifact_origin=path_artifact_origin,
            artifact_url=artifact_url,
            artifact_sha256=artifact_sha256,
            dynamic_runtime=dynamic_runtime,
            runtime_timeout_seconds=runtime_timeout_seconds,
            include_posture=include_posture,
            required_providers=frozenset(
                str(provider).strip().lower()
                for provider in (required_providers or ())
                if str(provider).strip()
            ),
        )
