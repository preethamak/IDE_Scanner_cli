from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import zipfile
from pathlib import Path
from typing import Any

MAX_ARCHIVE_FILES = 100_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_COMPRESSION_RATIO = 100
MAX_INVENTORY_FILES = 100_000
MAX_GZIP_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_GZIP_COMPRESSION_RATIO = 100
BINARY_RISK_EXTS = {".dll", ".dylib", ".exe", ".node", ".so"}
PACKED_RISK_EXTS = {".7z", ".asar", ".gz", ".jar", ".rar", ".tar", ".tgz", ".war", ".zip"}


def extract_vsix(vsix_path: Path, destination: Path) -> dict[str, list[str]]:
    """Extract untrusted VSIX bytes without following archive-controlled links."""
    root = destination.resolve()
    anomalies: dict[str, list[str]] = {
        "traversal_members": [],
        "symlink_members": [],
        "special_members": [],
    }
    with zipfile.ZipFile(vsix_path) as archive:
        members = archive.infolist()
        files = [member for member in members if member.filename and not member.is_dir()]
        total_size = sum(member.file_size for member in files)
        compressed_size = sum(max(1, member.compress_size) for member in files)
        if len(files) > MAX_ARCHIVE_FILES:
            raise ValueError(f"VSIX contains too many files ({len(files)} > {MAX_ARCHIVE_FILES})")
        if total_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise ValueError("VSIX uncompressed size exceeds the extraction limit")
        if total_size / max(1, compressed_size) > MAX_ARCHIVE_COMPRESSION_RATIO:
            raise ValueError("VSIX compression ratio exceeds the extraction limit")

        extracted_bytes = 0
        for member in members:
            name = member.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            mode = (member.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                anomalies["symlink_members"].append(name)
                continue
            if mode and mode not in (0o100000, 0o040000):
                anomalies["special_members"].append(name)
                continue
            target = (root / name).resolve()
            try:
                target.relative_to(root)
            except ValueError:
                anomalies["traversal_members"].append(name)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("xb") as handle:
                while chunk := source.read(1024 * 1024):
                    extracted_bytes += len(chunk)
                    if extracted_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                        raise ValueError("VSIX extracted bytes exceeded the extraction limit")
                    handle.write(chunk)
    return {key: value for key, value in anomalies.items() if value}


def inventory_artifact(root: Path, targets_path: Path) -> dict[str, Any]:
    """Hash a validated relative-path manifest without escaping its artifact root."""
    root = root.resolve()
    raw_targets = json.loads(targets_path.read_text(encoding="utf-8"))
    if not isinstance(raw_targets, list) or any(not isinstance(item, str) or not item for item in raw_targets):
        raise ValueError("inventory target manifest must be a list of relative paths")
    targets = raw_targets
    if len(targets) > MAX_INVENTORY_FILES:
        raise ValueError(f"artifact contains too many files ({len(targets)} > {MAX_INVENTORY_FILES})")
    package_digest = hashlib.sha256()
    all_hashes: list[dict[str, Any]] = []
    risky_artifacts: list[dict[str, Any]] = []
    total_bytes = 0
    for rel in sorted(targets):
        if "\0" in rel or Path(rel).is_absolute():
            raise ValueError(f"invalid inventory target: {rel!r}")
        candidate = root.joinpath(*rel.split("/"))
        try:
            candidate.parent.resolve().relative_to(root)
        except ValueError as exc:
            raise ValueError(f"inventory target escapes artifact root: {rel}") from exc
        if candidate.is_symlink():
            target = os.readlink(candidate)
            encoded = target.encode("utf-8", errors="replace")
            digest = hashlib.sha256(encoded).hexdigest()
            entry = {"path": rel, "sha256": digest, "size_bytes": len(encoded), "kind": "symlink", "target": target}
            all_hashes.append(entry)
            risky_artifacts.append(dict(entry))
            package_digest.update(rel.encode("utf-8"))
            package_digest.update(b"\0symlink\0")
            package_digest.update(encoded)
            package_digest.update(b"\0")
            continue
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"inventory target escapes artifact root: {rel}") from exc
        if not resolved.is_file():
            raise ValueError(f"inventory target is not a regular file: {rel}")
        digest, size = _hash_file(resolved)
        total_bytes += size
        entry = {"path": rel, "sha256": digest, "size_bytes": size}
        all_hashes.append(entry)
        package_digest.update(rel.encode("utf-8"))
        package_digest.update(b"\0")
        package_digest.update(digest.encode("ascii"))
        package_digest.update(b"\0")
        suffix = resolved.suffix.lower()
        if suffix in BINARY_RISK_EXTS or suffix in PACKED_RISK_EXTS:
            risky_artifacts.append({**entry, "kind": "native" if suffix in BINARY_RISK_EXTS else "packed"})
    return {
        "hash_algorithm": "sha256",
        "package_hash": package_digest.hexdigest() if all_hashes else "",
        "files_hashed": len(all_hashes),
        "total_bytes_hashed": total_bytes,
        "risky_artifacts": risky_artifacts,
        "known_bad_matches": [],
        "vsix_signature": {"present": False, "verified": False, "verification_supported": False, "reason": "not-vsix"},
        "_all_file_hashes": all_hashes,
    }


def unwrap_gzip(source_path: Path, destination_path: Path) -> dict[str, Any]:
    """Expand one gzip layer with explicit output and compression-ratio caps."""
    compressed_size = source_path.stat().st_size
    if compressed_size <= 0:
        raise ValueError("gzip input is empty")
    written = 0
    digest = hashlib.sha256()
    try:
        with gzip.open(source_path, "rb") as source, destination_path.open("xb") as target:
            while chunk := source.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_GZIP_EXPANDED_BYTES:
                    raise ValueError("gzip expanded size exceeds the artifact limit")
                if written / compressed_size > MAX_GZIP_COMPRESSION_RATIO:
                    raise ValueError("gzip compression ratio exceeds the artifact limit")
                target.write(chunk)
                digest.update(chunk)
    except Exception:
        destination_path.unlink(missing_ok=True)
        raise
    if written == 0:
        destination_path.unlink(missing_ok=True)
        raise ValueError("gzip payload is empty")
    return {"expanded_bytes": written, "sha256": digest.hexdigest()}


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolated VSIX artifact worker")
    parser.add_argument("--operation", choices=("extract", "inventory", "unwrap-gzip"), default="extract")
    parser.add_argument("--vsix")
    parser.add_argument("--destination")
    parser.add_argument("--root")
    parser.add_argument("--targets")
    parser.add_argument("--input")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        if args.operation == "extract":
            if not args.vsix or not args.destination:
                raise ValueError("extract operation requires --vsix and --destination")
            result = {"anomalies": extract_vsix(Path(args.vsix), Path(args.destination))}
        elif args.operation == "inventory":
            if not args.root or not args.targets:
                raise ValueError("inventory operation requires --root and --targets")
            result = {"inventory": inventory_artifact(Path(args.root), Path(args.targets))}
        else:
            if not args.input or not args.output:
                raise ValueError("unwrap-gzip operation requires --input and --output")
            result = {"gzip": unwrap_gzip(Path(args.input), Path(args.output))}
        _emit({"schema_version": "1", "status": "complete", **result})
        return 0
    except Exception as exc:
        _emit({"schema_version": "1", "status": "failed", "error": _bounded_error(exc)})
        return 1


def _bounded_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"[:500]


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
