from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

MAX_MATCHES = 1_000
MAX_ERRORS = 50


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolated yara-python scanner worker")
    parser.add_argument("--root", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--targets", required=True)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    rules_path = Path(args.rules).resolve()
    targets_path = Path(args.targets)
    try:
        import yara  # type: ignore[import-not-found]

        rules = yara.compile(filepath=str(rules_path))
        matches: list[dict[str, str]] = []
        errors: list[dict[str, str]] = []
        scanned_files = 0
        truncated = False
        for raw in targets_path.read_text(encoding="utf-8").splitlines():
            rel = raw.strip()
            if not rel:
                continue
            candidate = root.joinpath(*rel.split("/"))
            try:
                resolved = candidate.resolve()
                resolved.relative_to(root)
                if not resolved.is_file() or candidate.is_symlink():
                    continue
                scanned_files += 1
                for match in rules.match(str(resolved), timeout=5):
                    if len(matches) >= MAX_MATCHES:
                        truncated = True
                        break
                    matches.append({"rule": str(match.rule), "path": rel})
            except Exception as exc:  # yara errors are isolated to one artifact member
                if len(errors) < MAX_ERRORS:
                    errors.append({"path": rel, "error": _bounded_error(exc)})
            if truncated:
                break
        _emit({
            "schema_version": "1",
            "files_analyzed": scanned_files,
            "matches": matches,
            "errors": errors,
            "truncated": truncated,
        })
        return 0 if not errors and not truncated else 2
    except Exception as exc:
        _emit({
            "schema_version": "1",
            "files_analyzed": 0,
            "matches": [],
            "errors": [{"path": "", "error": _bounded_error(exc)}],
            "truncated": False,
        })
        return 1


def _bounded_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"[:500]


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
