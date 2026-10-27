from __future__ import annotations

from dataclasses import dataclass
import re

from .types import PackageSourceEnum


@dataclass(frozen=True)
class ParsedPackage:
    source: PackageSourceEnum
    package_name: str


class PackageParser:
    """Neutral install-command parser used by the OSV pipeline."""

    def parse(self, command: str, *, repo_url: str | None = None) -> ParsedPackage:
        text = command.strip()
        lowered = text.lower()
        patterns = (
            (r"(?:^|\s)npx\s+(?:-y\s+)?([^\s]+)", PackageSourceEnum.NPX),
            (r"(?:^|\s)(?:uvx|pipx)\s+(?:--[^\s]+\s+)*([^\s]+)", PackageSourceEnum.UVX),
            (r"(?:^|\s)uv\s+tool\s+run\s+([^\s]+)", PackageSourceEnum.UV),
            (r"(?:^|\s)python(?:3)?\s+-m\s+([^\s]+)", PackageSourceEnum.PYTHON),
            (r"(?:^|\s)pip(?:3)?\s+install\s+(?:-[^\s]+\s+)*([^\s]+)", PackageSourceEnum.PYTHON),
        )
        if lowered.startswith("docker ") or lowered.startswith("docker:"):
            return ParsedPackage(PackageSourceEnum.DOCKER, text.split()[-1])
        for pattern, source in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                return ParsedPackage(source, match.group(1).split("@")[0] if source == PackageSourceEnum.PYTHON else match.group(1))
        if repo_url:
            return ParsedPackage(PackageSourceEnum.MISC, repo_url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git"))
        return ParsedPackage(PackageSourceEnum.MISC, text.split()[-1] if text else "")

