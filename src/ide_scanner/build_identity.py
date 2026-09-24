"""Resolve the scanner build identity used in reports and publication gates."""

from __future__ import annotations

import os
import re
from pathlib import Path


GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


def _git_directory(package_root: Path) -> Path | None:
    """Resolve the checkout's Git directory without invoking Git.

    The scanner's corpus scheduler deliberately replaces ``Popen`` in its
    serial path. Build identity lookup must therefore stay a pure filesystem
    operation. Supporting a ``.git`` file also keeps this working in linked
    worktrees, where Git stores the actual metadata elsewhere.
    """
    marker = package_root / ".git"
    try:
        if marker.is_dir():
            return marker
        if marker.is_file():
            contents = marker.read_text(encoding="utf-8").strip()
            prefix = "gitdir:"
            if contents.lower().startswith(prefix):
                target = contents[len(prefix) :].strip()
                if target:
                    resolved = Path(target)
                    return (package_root / resolved).resolve() if not resolved.is_absolute() else resolved
    except (OSError, UnicodeError):
        return None
    return None


def _resolve_git_head(package_root: Path) -> str:
    """Read the full HEAD SHA from loose or packed Git refs."""
    git_dir = _git_directory(package_root)
    if git_dir is None:
        return "unknown"
    try:
        head = (git_dir / "HEAD").read_text(encoding="ascii").strip()
        if GIT_SHA_RE.fullmatch(head):
            return head.lower()
        prefix = "ref: "
        if not head.startswith(prefix):
            return "unknown"
        ref = head[len(prefix) :].strip()
        if not ref or any(part in {"", ".", ".."} for part in ref.split("/")):
            return "unknown"

        try:
            loose = (git_dir / ref).read_text(encoding="ascii").strip()
        except FileNotFoundError:
            loose = ""
        if GIT_SHA_RE.fullmatch(loose):
            return loose.lower()

        packed = git_dir / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="ascii").splitlines():
                if line.startswith(("#", "^")):
                    continue
                fields = line.split(" ", 1)
                if len(fields) == 2 and fields[1].strip() == ref and GIT_SHA_RE.fullmatch(fields[0]):
                    return fields[0].lower()
    except (OSError, UnicodeError):
        return "unknown"
    return "unknown"


def scanner_build() -> str:
    """Return a verifiable scanner revision, or ``unknown``.

    CI supplies the immutable revision explicitly. A source checkout can
    resolve its own HEAD for local CLI use, while an installed package that
    is no longer inside a Git checkout remains explicitly unidentified.
    Short refs and arbitrary environment values never become metadata.
    """
    configured = os.environ.get("IDE_SCANNER_BUILD_SHA", "").strip().lower()
    if configured:
        return configured if GIT_SHA_RE.fullmatch(configured) else "unknown"

    package_root = Path(__file__).resolve().parents[2]
    return _resolve_git_head(package_root)
