from __future__ import annotations

import argparse
import email
import zipfile
from pathlib import Path


REQUIRED_FILES = {
    "guardrails_cli/engine_source.json",
    "ide_scanner/provider_rules/semgrep/vscode-security.yml",
    "ide_scanner/provider_rules/yara/ide-scanner.yar",
}


def verify_wheel(path: Path, *, expected_version: str) -> None:
    failures: list[str] = []
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        entry_point_names = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        if len(metadata_names) != 1:
            failures.append("wheel must contain exactly one METADATA file")
            metadata = None
            metadata_text = ""
        else:
            metadata_text = archive.read(metadata_names[0]).decode("utf-8")
            metadata = email.message_from_string(metadata_text)
        if metadata is not None:
            if metadata.get("Name") != "guardlens":
                failures.append(f"package name is {metadata.get('Name')!r}, expected 'guardlens'")
            if metadata.get("Version") != expected_version:
                failures.append(
                    f"package version is {metadata.get('Version')!r}, expected {expected_version!r}"
                )
            requirements = "\n".join(metadata.get_all("Requires-Dist") or [])
            if "guardlens-core" in requirements.lower():
                failures.append("wheel depends on the retired guardlens-core project")
        if not REQUIRED_FILES.issubset(names):
            failures.extend(f"wheel is missing {name}" for name in sorted(REQUIRED_FILES - names))
        if len(entry_point_names) != 1:
            failures.append("wheel must contain exactly one entry_points.txt file")
        elif "guardrails = guardrails_cli.main:main" not in archive.read(entry_point_names[0]).decode("utf-8"):
            failures.append("wheel does not expose the guardrails command")
        if "github.com/preethamak" in metadata_text.lower():
            failures.append("public package metadata contains a private source repository URL")
    if failures:
        raise SystemExit("Release verification failed:\n- " + "\n- ".join(failures))


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a Guardrails release wheel.")
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    verify_wheel(args.wheel, expected_version=args.version)
    print(f"Verified {args.wheel.name} as Guardrails {args.version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
