from __future__ import annotations

import argparse
import json
from importlib.metadata import PackageNotFoundError, distribution
from importlib.resources import files


ENGINE_DISTRIBUTION = "guardlens-core"


def verify() -> None:
    try:
        identity = json.loads(files("guardrails_cli").joinpath("engine_distribution.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Scanner distribution identity is unreadable: {exc}") from exc
    expected_name = identity.get("distribution")
    expected_version = identity.get("version")
    if expected_name != ENGINE_DISTRIBUTION or not isinstance(expected_version, str):
        raise SystemExit("Scanner distribution identity is invalid.")
    try:
        package = distribution(ENGINE_DISTRIBUTION)
    except PackageNotFoundError as exc:
        raise SystemExit("guardlens-core is not installed.") from exc
    if package.version != expected_version:
        raise SystemExit(f"Expected guardlens-core {expected_version}, found {package.version}.")
    records = [
        path
        for path in package.files or []
        if str(path).startswith("ide_scanner/")
        and path.hash is not None
        and path.suffix != ".pyc"
        and "__pycache__" not in path.parts
    ]
    if not records or any(path.hash is None for path in records):
        raise SystemExit("guardlens-core does not have hash-recorded scanner files.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Guardrails' installed scanner distribution.")
    parser.add_argument("--check", action="store_true", help="Verify the installed scanner distribution.")
    args = parser.parse_args()
    if not args.check:
        parser.error("--check is required")
    verify()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
