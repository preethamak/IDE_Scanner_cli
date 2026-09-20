from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
from zipfile import BadZipFile, ZipFile

MAX_REMOTE_ARTIFACT_BYTES = 512 * 1024 * 1024
REMOTE_ARTIFACT_TIMEOUT_SECONDS = 60


class ArtifactInputError(RuntimeError):
    """Raised when an external artifact cannot be acquired safely."""


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        parsed = urlparse(newurl)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
            raise ArtifactInputError("Artifact URL redirect must remain public HTTPS on port 443 without credentials")
        _require_public_host(parsed.hostname)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def acquire_https_vsix(url: str, expected_sha256: str, destination_dir: Path | None = None) -> Path:
    """Download a hash-pinned public HTTPS VSIX without following redirects."""
    expected = expected_sha256.strip().lower()
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise ArtifactInputError("A valid expected SHA-256 is required for direct artifact URLs")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ArtifactInputError("Artifact URL must be public HTTPS without embedded credentials")
    if parsed.port not in (None, 443):
        raise ArtifactInputError("Artifact URL must use the standard HTTPS port")
    _require_public_host(parsed.hostname)

    destination = Path(destination_dir) if destination_dir else Path(tempfile.gettempdir())
    destination.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="ide-scanner-url-", suffix=".vsix", dir=str(destination))
    path = Path(name)
    digest = hashlib.sha256()
    written = 0
    try:
        opener = urllib.request.build_opener(_SafeRedirect())
        request = urllib.request.Request(url, headers={"Accept": "application/octet-stream", "User-Agent": "ide-scanner/0.2"})
        with os.fdopen(fd, "wb") as target, opener.open(request, timeout=REMOTE_ARTIFACT_TIMEOUT_SECONDS) as response:
            while chunk := response.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_REMOTE_ARTIFACT_BYTES:
                    raise ArtifactInputError("Remote artifact exceeds the 512 MiB acquisition limit")
                target.write(chunk)
                digest.update(chunk)
        if written == 0:
            raise ArtifactInputError("Remote artifact is empty")
        if digest.hexdigest() != expected:
            raise ArtifactInputError("Remote artifact SHA-256 does not match the required digest")
        return path
    except (OSError, urllib.error.URLError, ArtifactInputError) as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        if isinstance(exc, ArtifactInputError):
            raise
        raise ArtifactInputError(f"Remote artifact acquisition failed: {exc}") from exc


def acquire_https_archive_member(
    url: str,
    archive_sha256: str,
    member: str,
    expected_sha256: str,
    destination_dir: Path | None = None,
) -> Path:
    """Acquire one hash-pinned VSIX member from a hash-pinned ZIP wrapper."""
    archive_hash = _validated_sha256(archive_sha256, "archive")
    member_hash = _validated_sha256(expected_sha256, "member")
    member_name = str(member or "").strip().replace("\\", "/")
    if not member_name or member_name.startswith("/") or ".." in Path(member_name).parts:
        raise ArtifactInputError("Archive member must be a relative path without parent traversal")
    destination = Path(destination_dir) if destination_dir else Path(tempfile.gettempdir())
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ide-scanner-archive-") as temporary:
        archive_path = acquire_https_vsix(url, archive_hash, Path(temporary))
        try:
            with ZipFile(archive_path) as archive:
                info = archive.getinfo(member_name)
                if info.is_dir() or info.file_size > MAX_REMOTE_ARTIFACT_BYTES:
                    raise ArtifactInputError("Archive member is empty or exceeds the 512 MiB acquisition limit")
                payload = archive.read(info)
        except (BadZipFile, KeyError, OSError, RuntimeError) as exc:
            raise ArtifactInputError(f"Remote archive member could not be read: {exc}") from exc
        if hashlib.sha256(payload).hexdigest() != member_hash:
            raise ArtifactInputError("Remote archive member SHA-256 does not match the required digest")
        fd, name = tempfile.mkstemp(prefix="ide-scanner-member-", suffix=".vsix", dir=str(destination))
        output = Path(name)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(payload)
            return output
        except OSError as exc:
            output.unlink(missing_ok=True)
            raise ArtifactInputError(f"Remote archive member could not be stored: {exc}") from exc


def _validated_sha256(value: str, label: str) -> str:
    digest = str(value or "").strip().lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ArtifactInputError(f"A valid {label} SHA-256 is required")
    return digest


def _require_public_host(hostname: str) -> None:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ArtifactInputError(f"Artifact host could not be resolved: {exc}") from exc
    if not addresses:
        raise ArtifactInputError("Artifact host did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ArtifactInputError(f"Artifact host resolves to a non-public address: {ip}")
