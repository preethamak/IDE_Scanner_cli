import json
import logging
import re
import tomllib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from typing import Optional

import json5
import yaml
from packaging.requirements import Requirement

from ..sca_support import run_subprocess_exec

logger = logging.getLogger(__name__)


@dataclass
class DependencyEntry:
    name: str
    version: Optional[str]


@dataclass
class LockfileParseResult:
    direct: set[str]
    transitive: set[str]
    direct_entries: list[DependencyEntry]
    transitive_entries: list[DependencyEntry]
    ecosystem: Optional[str] = None


def _add_dependency_entry(
    entries: list[DependencyEntry],
    seen: set[tuple[str, Optional[str]]],
    name: Optional[str],
    version: Optional[str],
) -> None:
    if not name:
        return
    key = (name, version)
    if key in seen:
        return
    seen.add(key)
    entries.append(DependencyEntry(name=name, version=version))


def _extract_version_from_requirement(req_str) -> Optional[str]:
    try:
        req = Requirement(str(req_str))
    except Exception:
        return None
    for spec in req.specifier:
        if spec.operator in ("==", "==="):
            return spec.version
    return None


def _parse_pnpm_selector(selector: str) -> tuple[Optional[str], Optional[str]]:
    sel = selector.lstrip("/")
    if not sel:
        return None, None
    sel = sel.split("(")[0].strip()
    if "@" in sel[1:]:
        name, version = sel.rsplit("@", 1)
    else:
        name, version = sel, None
    return name, version


class LockfileParser(ABC):
    @abstractmethod
    async def parse(self, lockfile_path: Path) -> LockfileParseResult: ...


# --- Javascript Lockfile Parsers ---


class PackageLockParser(LockfileParser):
    async def parse(self, lockfile_path: Path) -> LockfileParseResult:

        all_deps, direct_deps = set(), set()
        direct_entries: list[DependencyEntry] = []
        trans_entries: list[DependencyEntry] = []
        direct_seen: set[tuple[str, Optional[str]]] = set()
        trans_seen: set[tuple[str, Optional[str]]] = set()

        try:
            with open(lockfile_path, "rb") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to parse package lock file - {e}")
            return LockfileParseResult(
                direct=direct_deps,
                transitive=all_deps,
                direct_entries=[],
                transitive_entries=[],
            )

        lockfile_version = data.get("lockfileVersion", 1)
        if lockfile_version >= 2:
            packages = data.get("packages", {})
            root_deps = packages.get("", {})
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                section_deps = root_deps.get(section, {})
                for name, version_spec in section_deps.items():
                    direct_deps.add(name)
                    version_val = version_spec if isinstance(version_spec, str) else None
                    all_deps.add(name)
                    _add_dependency_entry(direct_entries, direct_seen, name, version_val)
                    _add_dependency_entry(trans_entries, trans_seen, name, version_val)
            for key, meta in packages.items():
                if key == "":
                    continue
                name = meta.get("name")
                if not name:
                    parts = key.split("/")
                    name = (
                        "/".join(parts[-2:])
                        if len(parts) >= 2 and parts[-2].startswith("@")
                        else parts[-1]
                    )
                if not name:
                    continue
                all_deps.add(name)
                _add_dependency_entry(trans_entries, trans_seen, name, meta.get("version"))
        else:
            deps = data.get("dependencies", {})
            for name, meta in deps.items():
                direct_deps.add(name)
                version_val = None
                if isinstance(meta, dict):
                    version_val = meta.get("version")
                elif isinstance(meta, str):
                    version_val = meta
                _add_dependency_entry(direct_entries, direct_seen, name, version_val)
                _add_dependency_entry(trans_entries, trans_seen, name, version_val)
                all_deps.add(name)

        transitive_deps = all_deps - direct_deps
        return LockfileParseResult(
            direct=direct_deps,
            transitive=transitive_deps,
            direct_entries=direct_entries,
            transitive_entries=trans_entries,
        )


class YarnLockParser(LockfileParser):
    async def parse(self, lockfile_path: Path) -> LockfileParseResult:

        all_deps, direct_deps = set(), set()
        direct_entries: list[DependencyEntry] = []
        trans_entries: list[DependencyEntry] = []
        direct_seen: set[tuple[str, Optional[str]]] = set()
        trans_seen: set[tuple[str, Optional[str]]] = set()

        try:
            current_selectors: list[str] = []
            current_version: Optional[str] = None

            def flush_current_block():
                if not current_selectors:
                    return
                for sel in current_selectors:
                    if not sel:
                        continue
                    selector = sel.strip().strip('"').strip("'")
                    name = selector.rsplit("@", 1)[0] if "@" in selector else selector
                    if name:
                        all_deps.add(name)
                        _add_dependency_entry(trans_entries, trans_seen, name, current_version)

            with open(lockfile_path, "r", encoding="utf-8", errors="ignore") as f:
                for raw_txt in f:
                    line = raw_txt.rstrip("\n")
                    if not line:
                        continue
                    if not line.startswith(" ") and line.endswith(":"):
                        flush_current_block()
                        key = line[:-1]
                        current_selectors = [s.strip() for s in key.split(",")]
                        current_version = None
                    elif line.startswith(" "):
                        stripped = line.strip()
                        if stripped.startswith("version "):
                            version_token = stripped.split(" ", 1)[1].strip()
                            current_version = version_token.strip('"')
            flush_current_block()
        except IOError as e:
            logger.warning(f"Failed to parse yarn lock file - {e}")
            return LockfileParseResult(
                direct=direct_deps,
                transitive=all_deps,
                direct_entries=[],
                transitive_entries=[],
            )

        package_json_path = lockfile_path.parent / "package.json"
        if package_json_path.exists():
            try:
                with open(package_json_path, "rb") as f:
                    package_json = json.load(f)
                for section in (
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                ):
                    d = package_json.get(section, {})
                    for name, spec in d.items():
                        direct_deps.add(name)
                        version_val = spec if isinstance(spec, str) else None
                        _add_dependency_entry(direct_entries, direct_seen, name, version_val)
                        _add_dependency_entry(trans_entries, trans_seen, name, version_val)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to parse package json file - {e}")

        transitive_deps = all_deps - direct_deps
        return LockfileParseResult(
            direct=direct_deps,
            transitive=transitive_deps,
            direct_entries=direct_entries,
            transitive_entries=trans_entries,
        )


class PnpmLockParser(LockfileParser):
    async def parse(self, lockfile_path: Path) -> LockfileParseResult:

        all_deps, direct_deps = set(), set()
        direct_entries: list[DependencyEntry] = []
        trans_entries: list[DependencyEntry] = []
        direct_seen: set[tuple[str, Optional[str]]] = set()
        trans_seen: set[tuple[str, Optional[str]]] = set()

        try:
            with open(lockfile_path, "rb") as f:
                data = yaml.safe_load(f)
        except (yaml.YAMLError, IOError) as e:
            logger.warning(f"Failed to parse pnpm lock file - {e}")
            return LockfileParseResult(
                direct=direct_deps,
                transitive=all_deps,
                direct_entries=[],
                transitive_entries=[],
            )

        packages = data.get("packages", {})
        for pkg in packages.keys():
            name, version = _parse_pnpm_selector(pkg)
            if name:
                all_deps.add(name)
                _add_dependency_entry(trans_entries, trans_seen, name, version)

        importers = data.get("importers", {})
        for imp in importers.values():
            for pnpm_section in (
                "dependencies",
                "optionalDependencies",
                "devDependencies",
            ):
                deps = imp.get(pnpm_section, {})
                for name, meta in deps.items():
                    direct_deps.add(name)
                    version_val = None
                    if isinstance(meta, dict):
                        version_val = meta.get("version")
                    elif isinstance(meta, str):
                        version_val = meta
                    _add_dependency_entry(direct_entries, direct_seen, name, version_val)
                    _add_dependency_entry(trans_entries, trans_seen, name, version_val)
                    all_deps.add(name)

        if not direct_deps:
            package_json_path = lockfile_path.parent / "package.json"
            if package_json_path.exists():
                try:
                    with open(package_json_path, "rb") as f:
                        package_json = json.load(f)
                    for section in (
                        "dependencies",
                        "devDependencies",
                        "optionalDependencies",
                    ):
                        deps = package_json.get(section, {})
                        for name, spec in deps.items():
                            direct_deps.add(name)
                            version_val = spec if isinstance(spec, str) else None
                            _add_dependency_entry(direct_entries, direct_seen, name, version_val)
                            _add_dependency_entry(trans_entries, trans_seen, name, version_val)
                            all_deps.add(name)
                except (json.JSONDecodeError, IOError) as e:
                    logger.warning(f"Failed to parse package json file - {e}")

        transitive_deps = all_deps - direct_deps
        return LockfileParseResult(
            direct=direct_deps,
            transitive=transitive_deps,
            direct_entries=direct_entries,
            transitive_entries=trans_entries,
        )


class BunLockParser(LockfileParser):
    async def parse(self, lockfile_path: Path) -> LockfileParseResult:

        all_deps, direct_deps = set(), set()
        direct_entries: list[DependencyEntry] = []
        trans_entries: list[DependencyEntry] = []
        direct_seen: set[tuple[str, Optional[str]]] = set()
        trans_seen: set[tuple[str, Optional[str]]] = set()

        try:
            with open(lockfile_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json5.load(f)
        except (ValueError, IOError) as e:
            logger.warning(f"Failed to parse bun lock file - {e}")
            return LockfileParseResult(
                direct=direct_deps,
                transitive=all_deps,
                direct_entries=[],
                transitive_entries=[],
            )

        packages = data.get("packages", {})
        for entry in packages.values():
            selector = entry[0] if isinstance(entry, list) and entry else None
            if selector:
                name = str(selector).strip().strip('"').strip("'")
                brace_idx = name.find("(")
                if brace_idx != -1:
                    name = name[:brace_idx].strip()
                version_val = None
                if "@" in name[1:]:
                    name, version_val = name.rsplit("@", 1)
                if name:
                    all_deps.add(name)
                    _add_dependency_entry(trans_entries, trans_seen, name, version_val)

        package_json_path = lockfile_path.parent / "package.json"
        if package_json_path.exists():
            try:
                with open(package_json_path, "rb") as f:
                    package_json = json.load(f)
                for section in (
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                ):
                    d = package_json.get(section, {})
                    for name, spec in d.items():
                        direct_deps.add(name)
                        version_val = spec if isinstance(spec, str) else None
                        _add_dependency_entry(direct_entries, direct_seen, name, version_val)
                        _add_dependency_entry(trans_entries, trans_seen, name, version_val)
                        all_deps.add(name)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to parse package json file - {e}")

        transitive_deps = all_deps - direct_deps
        return LockfileParseResult(
            direct=direct_deps,
            transitive=transitive_deps,
            direct_entries=direct_entries,
            transitive_entries=trans_entries,
        )


# --- Python Lockfile Parsers ---


class UVLockParser(LockfileParser):
    async def parse(self, lockfile_path: Path) -> LockfileParseResult:

        all_deps, direct_deps = set(), set()
        direct_entries: list[DependencyEntry] = []
        trans_entries: list[DependencyEntry] = []
        direct_seen: set[tuple[str, Optional[str]]] = set()
        trans_seen: set[tuple[str, Optional[str]]] = set()
        try:
            with open(lockfile_path, "rb") as f:
                data = tomllib.load(f)

            packages = data.get("package", [])
            for pkg in packages:
                name = pkg.get("name")
                version = pkg.get("version")
                if name:
                    all_deps.add(name)
                    _add_dependency_entry(trans_entries, trans_seen, name, version)
        except (tomllib.TOMLDecodeError, UnicodeDecodeError, Exception):
            with open(lockfile_path, "r", encoding="utf-8", errors="ignore") as f:
                for raw_txt in f:
                    line = raw_txt.split("#", 1)[0].split(";", 1)[0].strip()
                    if not line:
                        continue
                    try:
                        name = Requirement(line).name
                        if name:
                            all_deps.add(name)
                            _add_dependency_entry(
                                trans_entries,
                                trans_seen,
                                name,
                                _extract_version_from_requirement(line),
                            )
                    except Exception:
                        req_match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
                        if req_match:
                            all_deps.add(req_match.group(1))
                            _add_dependency_entry(
                                trans_entries, trans_seen, req_match.group(1), None
                            )

        pyproject_path = lockfile_path.parent / "pyproject.toml"

        if pyproject_path.exists():
            try:
                with open(pyproject_path, "rb") as f:
                    pyproject = tomllib.load(f)

                project_deps = pyproject.get("project", {}).get("dependencies", [])
                dev_deps = pyproject.get("tool", {}).get("uv", {}).get(
                    "dev-dependencies", []
                ) or pyproject.get("dependency-groups", {}).get("dev", [])

                for s in chain(project_deps, dev_deps):
                    try:
                        req = Requirement(str(s))
                        name = req.name
                        version_val = _extract_version_from_requirement(str(s))
                    except Exception:
                        name = str(s)
                        version_val = None
                    if name:
                        direct_deps.add(name)
                        _add_dependency_entry(direct_entries, direct_seen, name, version_val)
                        _add_dependency_entry(trans_entries, trans_seen, name, version_val)
            except (tomllib.TOMLDecodeError, IOError) as e:
                logger.warning(f"Failed to parse pyproject file - {e}")

        transitive_deps = all_deps - direct_deps
        return LockfileParseResult(
            direct=direct_deps,
            transitive=transitive_deps,
            direct_entries=direct_entries,
            transitive_entries=trans_entries,
        )


class RequirementsTxtParser(LockfileParser):
    async def parse(self, lockfile_path: Path) -> LockfileParseResult:

        direct_deps = set()
        direct_entries: list[DependencyEntry] = []
        direct_seen: set[tuple[str, Optional[str]]] = set()
        try:
            with open(lockfile_path, "r", encoding="utf-8", errors="ignore") as f:
                for raw_txt in f:
                    line = raw_txt.split("#", 1)[0].split(";", 1)[0].strip()
                    if not line:
                        continue
                    try:
                        name = Requirement(line).name
                        if name:
                            direct_deps.add(name)
                            _add_dependency_entry(
                                direct_entries,
                                direct_seen,
                                name,
                                _extract_version_from_requirement(line),
                            )
                    except Exception:
                        req_match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
                        if req_match:
                            pkg_name = req_match.group(1)
                            direct_deps.add(pkg_name)
                            _add_dependency_entry(direct_entries, direct_seen, pkg_name, None)
        except IOError as e:
            logger.warning(f"Failed to parse requirements txt file - {e}")

        return LockfileParseResult(
            direct=direct_deps,
            transitive=set(),
            direct_entries=direct_entries,
            transitive_entries=[],
        )


# --- Rust Lockfile Parsers ---


class CargoLockParser(LockfileParser):
    async def parse(self, lockfile_path: Path) -> LockfileParseResult:

        all_deps, direct_deps = set(), set()
        direct_entries: list[DependencyEntry] = []
        trans_entries: list[DependencyEntry] = []
        direct_seen: set[tuple[str, Optional[str]]] = set()
        trans_seen: set[tuple[str, Optional[str]]] = set()
        try:
            with open(lockfile_path, "rb") as f:
                data = tomllib.load(f)
        except (tomllib.TOMLDecodeError, IOError) as e:
            logger.warning(f"Failed to parse cargo lock file - {e}")
            return LockfileParseResult(
                direct=direct_deps,
                transitive=all_deps,
                direct_entries=[],
                transitive_entries=[],
            )

        packages = data.get("package", [])
        for pkg in packages:
            name = pkg.get("name")
            version = pkg.get("version")
            if name:
                all_deps.add(name)
                _add_dependency_entry(trans_entries, trans_seen, name, version)

        cargo_toml_path = lockfile_path.parent / "Cargo.toml"
        if cargo_toml_path.exists():
            try:
                with open(cargo_toml_path, "rb") as f:
                    cargo = tomllib.load(f)

                for section in (
                    "dependencies",
                    "dev-dependencies",
                    "build-dependencies",
                ):
                    sec = cargo.get(section, {})
                    for name, meta in sec.items():
                        direct_deps.add(name)
                        version_val = None
                        if isinstance(meta, dict):
                            version_val = meta.get("version")
                        elif isinstance(meta, str):
                            version_val = meta
                        _add_dependency_entry(direct_entries, direct_seen, name, version_val)
                        _add_dependency_entry(trans_entries, trans_seen, name, version_val)
            except (tomllib.TOMLDecodeError, IOError) as e:
                logger.warning(f"Failed to parse cargo toml file - {e}")

        transitive_deps = all_deps - direct_deps
        return LockfileParseResult(
            direct=direct_deps,
            transitive=transitive_deps,
            direct_entries=direct_entries,
            transitive_entries=trans_entries,
        )


# --- Go Lockfile Parsers ---
class GoModParser(LockfileParser):
    async def parse(self, lockfile_path: Path) -> LockfileParseResult:

        go_mod_dir = lockfile_path.parent

        all_deps, direct_deps = set(), set()
        direct_entries: list[DependencyEntry] = []
        trans_entries: list[DependencyEntry] = []
        direct_seen: set[tuple[str, Optional[str]]] = set()
        trans_seen: set[tuple[str, Optional[str]]] = set()

        try:
            stdout, _, returncode = await run_subprocess_exec(
                ["go", "mod", "edit", "-json"],
                timeout=20,
                cwd=go_mod_dir,
            )
            if returncode == 0 and stdout:
                mod_json = json.loads(stdout.decode("utf-8"))
                for req in mod_json.get("Require") or []:
                    if req.get("Path") and not req.get("Indirect"):
                        direct_deps.add(req["Path"])
                        version_val = req.get("Version")
                        _add_dependency_entry(direct_entries, direct_seen, req["Path"], version_val)
                        _add_dependency_entry(trans_entries, trans_seen, req["Path"], version_val)
        except Exception:
            logger.warning("Failed to run go mod edit ... ")
            return LockfileParseResult(
                direct=set(), transitive=set(), direct_entries=[], transitive_entries=[]
            )

        try:
            stdout, _, returncode = await run_subprocess_exec(
                ["go", "list", "-m", "-json", "all"],
                timeout=20,
                cwd=go_mod_dir,
            )
            if returncode == 0 and stdout:
                chunk_chars = []
                brace_depth = 0
                for char in stdout.decode("utf-8"):
                    if char == "{":
                        brace_depth += 1
                    if brace_depth:
                        chunk_chars.append(char)
                    if char == "}":
                        brace_depth -= 1
                        if brace_depth == 0:
                            try:
                                module_info = json.loads("".join(chunk_chars))
                                module_path = module_info.get("Path")
                                if module_path and not module_info.get("Main", False):
                                    all_deps.add(module_path)
                                    _add_dependency_entry(
                                        trans_entries,
                                        trans_seen,
                                        module_path,
                                        module_info.get("Version"),
                                    )
                            finally:
                                chunk_chars.clear()
        except Exception:
            logger.warning("Failed to run go list ...")
            return LockfileParseResult(
                direct=set(), transitive=set(), direct_entries=[], transitive_entries=[]
            )

        transitive_deps = all_deps - direct_deps if all_deps else set()
        return LockfileParseResult(
            direct=direct_deps,
            transitive=transitive_deps,
            direct_entries=direct_entries,
            transitive_entries=trans_entries,
        )


LOCKFILE_PARSERS = {
    # --- Javascript Lockfiles ---
    "package-lock.json": PackageLockParser(),
    "yarn.lock": YarnLockParser(),
    "pnpm-lock.yaml": PnpmLockParser(),
    "bun.lock": BunLockParser(),
    # --- Python Lockfiles ---
    "uv.lock": UVLockParser(),
    "requirements.txt": RequirementsTxtParser(),
    # --- Rust Lockfiles ---
    "Cargo.lock": CargoLockParser(),
    # --- Go Lockfiles ---
    "go.mod": GoModParser(),
}

LOCKFILE_ECOSYSTEMS = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lock": "npm",
    "uv.lock": "pypi",
    "requirements.txt": "pypi",
    "Cargo.lock": "cargo",
    "go.mod": "golang",
}


async def parse_lockfile(path_str: str) -> LockfileParseResult:
    p = Path(path_str)
    parser = LOCKFILE_PARSERS.get(p.name)
    if parser:
        result = await parser.parse(p)
        result.ecosystem = LOCKFILE_ECOSYSTEMS.get(p.name)
        return result
    return LockfileParseResult(
        direct=set(), transitive=set(), direct_entries=[], transitive_entries=[]
    )


__all__ = ["parse_lockfile", "LOCKFILE_PARSERS"]

