from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

TARGET_PLATFORM_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
REGISTRIES = frozenset({"vs-marketplace", "openvsx"})
SCHEMA_VERSION = 1


class ArtifactStoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredArtifact:
    path: Path
    backend: str
    storage_key: str
    sha256: str
    size_bytes: int
    extension_id: str
    version: str
    registry: str
    target_platform: str
    first_seen: str
    last_seen: str


class ArtifactStore(Protocol):
    def preserve(self, source: Path, *, extension_id: str, version: str, registry: str,
                 target_platform: str = "") -> StoredArtifact: ...


class FilesystemArtifactStore:
    """Private, content-addressed VSIX vault with an observation catalog."""

    def __init__(self, root: Path | str):
        try:
            self.root = Path(root).expanduser().resolve()
            self.objects = self.root / "sha256"
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._require_directory(self.root, "vault root")
            self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._require_directory(self.objects, "object directory")
            os.chmod(self.root, 0o700)
            os.chmod(self.objects, 0o700)
            self.catalog = self.root / "catalog.sqlite3"
            if self.catalog.is_symlink() or (self.catalog.exists() and not self.catalog.is_file()):
                raise ArtifactStoreError("Artifact catalog must be a regular file.")
            self._initialize()
        except ArtifactStoreError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ArtifactStoreError(f"Could not initialize artifact store: {exc}") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.catalog, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS artifacts (
                    sha256 TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL,
                    storage_key TEXT NOT NULL UNIQUE, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS observations (
                    extension_id TEXT NOT NULL, version TEXT NOT NULL, registry TEXT NOT NULL,
                    target_platform TEXT NOT NULL, sha256 TEXT NOT NULL,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    PRIMARY KEY (extension_id, version, registry, target_platform, sha256),
                    FOREIGN KEY (sha256) REFERENCES artifacts(sha256)
                );
                CREATE INDEX IF NOT EXISTS observations_sha256_idx ON observations(sha256);
                CREATE INDEX IF NOT EXISTS observations_platform_idx ON observations(target_platform);
                CREATE INDEX IF NOT EXISTS observations_registry_idx ON observations(registry);
                CREATE INDEX IF NOT EXISTS observations_last_seen_idx ON observations(last_seen);
            """)
            version = int(db.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise ArtifactStoreError(f"Artifact catalog schema {version} is newer than supported schema {SCHEMA_VERSION}.")
            db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        os.chmod(self.catalog, 0o600)

    def preserve(self, source: Path, *, extension_id: str, version: str, registry: str,
                 target_platform: str = "") -> StoredArtifact:
        platform = str(target_platform or "").strip().lower()
        if platform and not TARGET_PLATFORM_RE.fullmatch(platform):
            raise ArtifactStoreError("Artifact target platform is invalid.")
        extension_id = self._identity(extension_id, "extension id", 255)
        version = self._identity(version, "version", 128)
        registry = self._identity(registry, "registry", 32).lower()
        if registry not in REGISTRIES:
            raise ArtifactStoreError("Artifact registry is invalid.")
        source = Path(source)
        if source.is_symlink() or not source.is_file():
            raise ArtifactStoreError("Artifact source must be a regular file.")
        fd, staged_name = tempfile.mkstemp(prefix=".staging-", dir=self.root)
        digest = hashlib.sha256()
        size = 0
        try:
            with source.open("rb") as incoming, os.fdopen(fd, "wb") as staged:
                while chunk := incoming.read(1024 * 1024):
                    staged.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                staged.flush()
                os.fsync(staged.fileno())
            if not size:
                raise ArtifactStoreError("Cannot preserve an empty artifact.")
            sha256 = digest.hexdigest()
            storage_key = f"sha256/{sha256[:2]}/{sha256}.vsix"
            destination = self.root / storage_key
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._require_directory(destination.parent, "hash directory")
            os.chmod(destination.parent, 0o700)
            if destination.exists():
                if destination.is_symlink() or not destination.is_file():
                    raise ArtifactStoreError("Content-addressed artifact must be a regular file.")
                self._verify(destination, sha256, size)
            else:
                try:
                    os.link(staged_name, destination)
                except FileExistsError:
                    if destination.is_symlink() or not destination.is_file():
                        raise ArtifactStoreError("Content-addressed artifact must be a regular file.")
                    self._verify(destination, sha256, size)
                self._fsync_directory(destination.parent)
            os.chmod(destination, 0o400)
            self._verify(destination, sha256, size)
            now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            with self._connect() as db:
                db.execute("INSERT INTO artifacts VALUES (?, ?, ?, ?, ?) ON CONFLICT(sha256) DO UPDATE SET last_seen=excluded.last_seen",
                           (sha256, size, storage_key, now, now))
                db.execute("""INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(extension_id, version, registry, target_platform, sha256)
                    DO UPDATE SET last_seen=excluded.last_seen""",
                           (extension_id, version, registry, platform, sha256, now, now))
                row = db.execute("""SELECT o.first_seen, o.last_seen FROM observations o
                    WHERE extension_id=? AND version=? AND registry=? AND target_platform=? AND sha256=?""",
                                 (extension_id, version, registry, platform, sha256)).fetchone()
            return StoredArtifact(destination, "filesystem", storage_key, sha256, size,
                                  extension_id, version, registry, platform, row[0], row[1])
        except ArtifactStoreError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ArtifactStoreError(f"Could not preserve artifact: {exc}") from exc
        finally:
            if staged_name:
                Path(staged_name).unlink(missing_ok=True)

    @staticmethod
    def _verify(path: Path, expected_hash: str, expected_size: int) -> None:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        if size != expected_size or digest.hexdigest() != expected_hash:
            raise ArtifactStoreError("Existing content-addressed artifact failed integrity validation.")

    def search(self, *, extension_id: str | None = None, version: str | None = None,
               registry: str | None = None, target_platform: str | None = None,
               sha256: str | None = None) -> list[dict[str, object]]:
        if target_platform is not None:
            target_platform = str(target_platform).strip().lower()
            if target_platform and not TARGET_PLATFORM_RE.fullmatch(target_platform):
                raise ArtifactStoreError("Artifact target platform is invalid.")
        if sha256 is not None:
            sha256 = str(sha256).strip().lower()
            if not SHA256_RE.fullmatch(sha256):
                raise ArtifactStoreError("Artifact SHA-256 is invalid.")
        clauses, values = [], []
        for column, value in (("o.extension_id", extension_id), ("o.version", version),
                              ("o.registry", registry), ("o.target_platform", target_platform),
                              ("o.sha256", sha256)):
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(value)
        query = """SELECT o.extension_id,o.version,o.registry,o.target_platform,o.sha256,
                   a.size_bytes,a.storage_key,o.first_seen,o.last_seen
                   FROM observations o JOIN artifacts a ON a.sha256=o.sha256"""
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY o.last_seen DESC"
        try:
            with self._connect() as db:
                return [dict(row) for row in db.execute(query, values)]
        except sqlite3.Error as exc:
            raise ArtifactStoreError(f"Could not search artifact catalog: {exc}") from exc

    @staticmethod
    def _identity(value: str, label: str, maximum: int) -> str:
        normalized = str(value or "").strip()
        if not normalized or len(normalized) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in normalized):
            raise ArtifactStoreError(f"Artifact {label} is invalid.")
        return normalized

    @staticmethod
    def _require_directory(path: Path, label: str) -> None:
        if path.is_symlink() or not path.is_dir():
            raise ArtifactStoreError(f"Artifact {label} must be a real directory.")

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def artifact_store_from_environment() -> FilesystemArtifactStore | None:
    configured = os.environ.get("IDE_SCANNER_ARTIFACT_STORE", "").strip()
    return FilesystemArtifactStore(configured) if configured else None
