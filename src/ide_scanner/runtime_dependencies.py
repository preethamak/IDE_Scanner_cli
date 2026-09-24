"""Pinned runtime sidecars required by extension dynamic probes.

Runtime sidecars are provisioned outside the Bubblewrap namespace. The
namespace receives only a hash-verified executable copied into the disposable
extension target. Missing or mismatched sidecars remain an explicit runtime
coverage failure; they are never replaced by a stub.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
from pathlib import Path
from typing import Any

RUNTIME_CACHE_ENV = "GUARDRAILS_RUNTIME_CACHE"

# This lock is deliberately small and exact. Add a new entry only after the
# upstream release asset and the decompressed executable have both been
# independently hashed and exercised in the runtime holdout.
RUNTIME_DEPENDENCY_LOCK: dict[str, dict[str, str]] = {
    "rust-analyzer:2026-07-13": {
        "dependency": "rust-analyzer",
        "release_tag": "2026-07-13",
        "version": "0.3.2971",
        "platform": "linux-x86_64",
        "asset_name": "rust-analyzer-x86_64-unknown-linux-gnu.gz",
        "asset_sha256": "5ee1754afa7a1eb7f56606847b61328e6fac2f316e40ebf314dcefb30263df4d",
        "binary_sha256": "73dc265a58f78a29d80d67319fe84c6a8f0b377bb161ffff2846e60a35620457",
        "cache_subpath": "rust-analyzer-2026-07-13/rust-analyzer",
        "download_url": "https://github.com/rust-lang/rust-analyzer/releases/download/2026-07-13/rust-analyzer-x86_64-unknown-linux-gnu.gz",
    },
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _default_cache_root() -> Path:
    configured = os.environ.get(RUNTIME_CACHE_ENV, "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".cache" / "guardrails" / "runtime"


def _rust_lock(manifest: dict[str, Any]) -> dict[str, str] | None:
    release_tag = str(manifest.get("releaseTag") or "").strip()
    version = str(manifest.get("version") or "").strip()
    if not release_tag:
        return None
    locked = RUNTIME_DEPENDENCY_LOCK.get(f"rust-analyzer:{release_tag}")
    if locked is None or locked.get("version") != version:
        return None
    if platform.system().lower() != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        return None
    return locked


def provision_for_extension(target: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Copy only a verified sidecar into ``target`` when the extension needs it."""
    languages = {
        str(item.get("id") or "").lower()
        for item in ((manifest.get("contributes") or {}).get("languages") or [])
        if isinstance(item, dict)
    }
    if "rust" not in languages:
        return []

    lock = _rust_lock(manifest)
    if lock is None:
        return [{
            "dependency": "rust-analyzer",
            "status": "unlocked-or-unsupported",
            "required": True,
            "reason": "no verified sidecar lock matches the extension release or host platform",
        }]

    packaged = target / "server" / "rust-analyzer"
    if packaged.is_file() and os.access(packaged, os.X_OK):
        actual = _sha256(packaged)
        if actual != lock["binary_sha256"]:
            return [{
                "dependency": lock["dependency"],
                "status": "packaged-hash-mismatch",
                "required": True,
                "version": lock["version"],
                "expected_sha256": lock["binary_sha256"],
                "actual_sha256": actual,
            }]
        return [{
            "dependency": lock["dependency"],
            "status": "packaged",
            "required": True,
            "version": lock["version"],
            "sha256": actual,
        }]

    cache_path = _default_cache_root() / lock["cache_subpath"]
    if not cache_path.is_file():
        return [{
            "dependency": lock["dependency"],
            "status": "missing-cache",
            "required": True,
            "version": lock["version"],
            "expected_sha256": lock["binary_sha256"],
            "cache_path": str(cache_path),
        }]
    actual = _sha256(cache_path)
    if actual != lock["binary_sha256"]:
        return [{
            "dependency": lock["dependency"],
            "status": "cache-hash-mismatch",
            "required": True,
            "version": lock["version"],
            "expected_sha256": lock["binary_sha256"],
            "actual_sha256": actual,
        }]

    packaged.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(cache_path, packaged)
    packaged.chmod(packaged.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return [{
        "dependency": lock["dependency"],
        "status": "provisioned",
        "required": True,
        "version": lock["version"],
        "sha256": actual,
        "source": "verified-cache",
    }]


def locked_downloads() -> list[dict[str, str]]:
    """Return immutable download metadata for the provisioning command."""
    return [dict(item) for item in RUNTIME_DEPENDENCY_LOCK.values()]
