from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "src" / "ide_scanner"
MANIFEST = ROOT / "src" / "guardrails_cli" / "engine_source.json"
IGNORED_PARTS = {"__pycache__"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_relative(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise SystemExit(f"Unsafe engine manifest path: {value!r}")
    return path


def target_files() -> set[str]:
    return {
        path.relative_to(TARGET).as_posix()
        for path in TARGET.rglob("*")
        if path.is_file()
        and not any(part in IGNORED_PARTS for part in path.parts)
        and path.suffix != ".pyc"
    }


def git(checkout: Path, *args: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(checkout), *args],
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"Could not read committed scanner source: {exc}") from exc


def sync(checkout: Path, revision: str, repository: str) -> None:
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision.lower()):
        raise SystemExit("--revision must be a full 40-character Git commit SHA.")
    resolved = git(checkout, "rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()
    if resolved != revision.lower():
        raise SystemExit(f"Revision resolved to {resolved}, not the requested {revision}.")
    files = [
        path
        for path in git(checkout, "ls-tree", "-r", "--name-only", revision, "--", "src/ide_scanner").decode().splitlines()
        if path
        and not any(part in IGNORED_PARTS for part in Path(path).parts)
        and Path(path).suffix != ".pyc"
    ]
    required = {"src/ide_scanner/__init__.py", "src/ide_scanner/scanner.py"}
    if not required.issubset(files):
        raise SystemExit(f"{checkout} does not contain a complete committed ide_scanner package.")

    hashes: dict[str, str] = {}
    for source_path in sorted(files):
        relative = safe_relative(Path(source_path).relative_to("src/ide_scanner").as_posix())
        destination = TARGET / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(git(checkout, "show", f"{revision}:{source_path}"))
        hashes[relative.as_posix()] = digest(destination)

    manifest = {
        "schema_version": 1,
        "source_repository": repository,
        "source_revision": revision.lower(),
        "files": hashes,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check() -> None:
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Engine source manifest is unreadable: {exc}") from exc

    expected = manifest.get("files")
    if not isinstance(expected, dict) or not expected:
        raise SystemExit("Engine source manifest contains no file hashes.")

    failures: list[str] = []
    for relative, expected_hash in sorted(expected.items()):
        path = TARGET / safe_relative(relative)
        if not path.is_file():
            failures.append(f"missing: {relative}")
        elif digest(path) != expected_hash:
            failures.append(f"changed: {relative}")
    for relative in sorted(target_files() - set(expected)):
        failures.append(f"unexpected: {relative}")
    if failures:
        raise SystemExit("Vendored scanner drift detected:\n" + "\n".join(failures))


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronize and verify Guardrails' bundled scanner engine.")
    parser.add_argument("--source-checkout", type=Path, help="Git checkout containing the committed scanner source.")
    parser.add_argument("--revision", help="Full source repository commit SHA.")
    parser.add_argument("--repository", default="https://github.com/preethamak/IDE_Scanner")
    parser.add_argument("--check", action="store_true", help="Verify the bundled files against the recorded hashes.")
    args = parser.parse_args()

    if args.check:
        check()
        return 0
    if args.source_checkout is None or not args.revision:
        parser.error("--source-checkout and --revision are required when synchronizing.")
    sync(args.source_checkout.resolve(), args.revision, args.repository)
    check()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
