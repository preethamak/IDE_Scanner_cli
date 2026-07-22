from __future__ import annotations

import os
import platform
from pathlib import Path


def discover_local_installations(extra_paths: list[Path] | None = None) -> list[dict[str, str]]:
    home = Path.home()
    candidates = [
        home / ".vscode" / "extensions",
        home / ".vscode-insiders" / "extensions",
        home / ".vscodium" / "extensions",
        home / ".cursor" / "extensions",
        home / ".windsurf" / "extensions",
    ]
    candidates.extend(extra_paths or [])

    system = platform.system().lower()
    if system == "darwin":
        candidates.extend([
            home / "Library" / "Application Support" / "Code" / "extensions",
            home / "Library" / "Application Support" / "Code - Insiders" / "extensions",
            home / "Library" / "Application Support" / "VSCodium" / "extensions",
            home / "Library" / "Application Support" / "Cursor" / "extensions",
            home / "Library" / "Application Support" / "Windsurf" / "extensions",
        ])
    elif system == "windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            base = Path(appdata)
            candidates.extend([
                base / "Code" / "extensions",
                base / "Code - Insiders" / "extensions",
                base / "VSCodium" / "extensions",
                base / "Cursor" / "extensions",
                base / "Windsurf" / "extensions",
            ])

    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for path in candidates:
        for target in discover_from_path(path):
            if target["path"] in seen:
                continue
            seen.add(target["path"])
            out.append(target)
    return out


def discover_from_path(path: Path | str) -> list[dict[str, str]]:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        return []
    if root.is_file():
        if root.suffix.lower() == ".vsix":
            return [{"type": "vsix", "path": str(root)}]
        return []
    if (root / "package.json").exists():
        return [{"type": "vscode", "path": str(root)}]

    out: list[dict[str, str]] = []
    try:
        children = list(root.iterdir())
    except OSError:
        return out
    for child in children:
        if child.name.startswith("."):
            continue
        if child.is_file() and child.suffix.lower() == ".vsix":
            out.append({"type": "vsix", "path": str(child)})
        elif child.is_dir() and (child / "package.json").exists():
            out.append({"type": "vscode", "path": str(child)})
    return out
