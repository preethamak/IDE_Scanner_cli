from __future__ import annotations

import posixpath
import re
from pathlib import PurePosixPath
from collections.abc import Iterator
from typing import Any

MAX_FLOW_MODULES = 10_000
MAX_FLOW_DEPTH = 24
MAX_FLOW_PATHS = 100_000


class FlowAnalysisLimitError(RuntimeError):
    """Raised when semantic-flow coverage cannot complete within its budget."""
_IMPORT_RE = re.compile(
    r"(?:\bfrom\s*['\"](?P<from>\.{1,2}/[^'\"]+)['\"]|"
    r"\brequire\s*\(\s*['\"](?P<require>\.{1,2}/[^'\"]+)['\"]\s*\)|"
    r"\bimport\s+[^;]*?\sfrom\s*['\"](?P<import>\.{1,2}/[^'\"]+)['\"]|"
    r"\bimport\s*\(\s*['\"](?P<dynamic>\.{1,2}/[^'\"]+)['\"]\s*\)|"
    r"\bimport\s*['\"](?P<side_effect>\.{1,2}/[^'\"]+)['\"])",
    re.M,
)
_DOWNLOAD = re.compile(r"(?:\bfetch\s*\(|\bhttps?\.(?:get|request)\b|\baxios\.get\b)")
_WRITE = re.compile(r"\b(?:fs\.(?:promises\.)?(?:writeFile|writeFileSync|createWriteStream)|workspace\.fs\.writeFile)\b")
_INSTALL = re.compile(r"workbench\.extensions\.installExtension")
_HASH = re.compile(r"createHash\s*\(\s*['\"]sha(?:256|384|512)['\"]", re.I)
_DIGEST = re.compile(r"\.digest\s*\(", re.I)
_EXPECTED = re.compile(r"(?:expected|trusted|pinned)(?:Hash|Digest|Sha256)|checksum", re.I)
_COMPARE = re.compile(r"(?:timingSafeEqual\s*\(|(?:===|!==)\s*(?:expected|trusted|pinned)|(?:expected|trusted|pinned)\w*\s*(?:===|!==))", re.I)
_SIGNATURE_VERIFY = re.compile(r"(?:crypto\.)?verify\s*\([^)]*,[^)]*,[^)]*\)|verifySignature\s*\(", re.I)
_FILE_READ = re.compile(r"\bfs\.(?:promises\.)?(?:readFile|readFileSync|createReadStream)\b")
_SERIALIZE = re.compile(r"\b(?:JSON\.stringify|Buffer\.from|createGzip|createCipheriv)\b")
_NETWORK_BODY = re.compile(r"\b(?:request|req)\.write\s*\(|\baxios\.(?:post|put)\s*\(|\bfetch\s*\([^)]*,\s*\{[^}]*\bbody\s*:", re.S)
_CREDENTIAL_FAMILIES = {
    "ssh": re.compile(r"\.ssh|id_(?:rsa|ed25519)", re.I),
    "cloud": re.compile(r"\.aws|\.azure|\.config/gcloud|cloud.*credential", re.I),
    "npm": re.compile(r"\.npmrc|npm.*token", re.I),
    "git": re.compile(r"\.git-credentials|github.*token|gitlab.*token", re.I),
    "wallet": re.compile(r"wallet|metamask|mnemonic|seed.?phrase", re.I),
    "environment": re.compile(r"(?:^|[/\\])\.env\b|process\.env", re.I),
}


def has_integrity_gate(text: str) -> bool:
    """Require verification plus comparison/gating, not a stray hash token."""
    return bool(_SIGNATURE_VERIFY.search(text)) or bool(
        _HASH.search(text) and _DIGEST.search(text) and _EXPECTED.search(text) and _COMPARE.search(text)
    )


def module_summary(rel: str, text: str, *, analyze_imports: bool = True) -> dict[str, Any]:
    # Bundler output contains module source and path strings that resemble live
    # relative imports but are no longer runtime edges. Preserve same-file
    # capability signals while avoiding a misleading graph for those blobs.
    imports = {
        _resolve_import(rel, next(value for value in match.groups() if value))
        for match in _IMPORT_RE.finditer(text)
    } if analyze_imports else set()
    return {
        "path": rel,
        "imports": sorted(imports),
        "download": bool(_DOWNLOAD.search(text)),
        "write": bool(_WRITE.search(text)),
        "install_vsix": bool(_INSTALL.search(text)),
        "integrity": has_integrity_gate(text),
        "credential_families": sorted(name for name, pattern in _CREDENTIAL_FAMILIES.items() if pattern.search(text)),
        "file_read": bool(_FILE_READ.search(text)),
        "serialize": bool(_SERIALIZE.search(text)),
        "network_body": bool(_NETWORK_BODY.search(text)),
    }


def remote_vsix_install_flow(
    modules: list[dict[str, Any]], entrypoints: set[str] | None = None
) -> dict[str, Any] | None:
    """Find a directed import path containing download, write, and install."""
    if len(modules) > MAX_FLOW_MODULES:
        raise FlowAnalysisLimitError(f"module count exceeds {MAX_FLOW_MODULES}")
    by_path, adjacency = _graph(modules)
    reachable = _reachable_modules(entrypoints, by_path, adjacency)
    for start in sorted(path for path, item in by_path.items() if item["download"] and path in reachable):
        for path in _directed_paths(start, adjacency):
            group = [by_path[module] for module in path]
            write_index = _first_stage_index(group, "write")
            install_index = _first_stage_index(group, "install_vsix", after=write_index)
            if (
                len(path) > 1
                and write_index is not None
                and install_index is not None
                and not any(item["integrity"] for item in group)
            ):
                return {
                    "files": path,
                    "import_path": path,
                    "stages": {
                        "download": [item["path"] for item in group if item["download"]],
                        "write": [item["path"] for item in group if item["write"]],
                        "install": [item["path"] for item in group if item["install_vsix"]],
                    },
                }
    return None


def credential_exfiltration_flow(
    modules: list[dict[str, Any]], entrypoints: set[str] | None = None
) -> dict[str, Any] | None:
    """Find a directed multi-module credential-read-to-network-body path."""
    if len(modules) > MAX_FLOW_MODULES:
        raise FlowAnalysisLimitError(f"module count exceeds {MAX_FLOW_MODULES}")
    by_path, adjacency = _graph(modules)
    reachable = _reachable_modules(entrypoints, by_path, adjacency)
    starts = sorted(
        path for path, item in by_path.items()
        if item["credential_families"] and item["file_read"] and path in reachable
    )
    for start in starts:
        for path in _directed_paths(start, adjacency):
            group = [by_path[module] for module in path]
            families = sorted({family for item in group for family in item["credential_families"]})
            serialization_index = _first_stage_index(group, "serialize")
            network_index = _first_stage_index(group, "network_body", after=serialization_index)
            if (
                len(path) > 1
                and len(families) >= 3
                and serialization_index is not None
                and network_index is not None
            ):
                return {
                    "files": path,
                    "import_path": path,
                    "credential_families": families,
                    "stages": {
                        "credential_read": [item["path"] for item in group if item["credential_families"] and item["file_read"]],
                        "serialization": [item["path"] for item in group if item["serialize"]],
                        "network_body": [item["path"] for item in group if item["network_body"]],
                    },
                }
    return None


def module_flow_coverage(
    modules: list[dict[str, Any]], entrypoints: set[str]
) -> dict[str, Any]:
    """Report graph completeness for reachable relative executable imports."""
    if len(modules) > MAX_FLOW_MODULES:
        raise FlowAnalysisLimitError(f"module count exceeds {MAX_FLOW_MODULES}")
    by_path, adjacency = _graph(modules)
    reachable = _reachable_modules(entrypoints, by_path, adjacency)
    unresolved: list[dict[str, str]] = []
    edge_count = 0
    for source in sorted(reachable):
        edge_count += len(adjacency.get(source, []))
        for target in by_path[source]["imports"]:
            if _match_module(target, by_path) is None and _is_executable_import(target):
                unresolved.append({"source": source, "target": target})
    return {
        "reachable_modules": len(reachable),
        "resolved_edges": edge_count,
        "unresolved_executable_imports": unresolved[:100],
        "unresolved_executable_import_count": len(unresolved),
    }


def _first_stage_index(
    modules: list[dict[str, Any]], stage: str, after: int | None = None
) -> int | None:
    start = 0 if after is None else after
    return next((index for index in range(start, len(modules)) if modules[index][stage]), None)


def _reachable_modules(
    entrypoints: set[str] | None,
    modules: dict[str, dict[str, Any]],
    adjacency: dict[str, list[str]],
) -> set[str]:
    if entrypoints is None:
        return set(modules)
    roots = {
        matched for entrypoint in entrypoints
        if (matched := _match_module(entrypoint, modules)) is not None
    }
    reachable: set[str] = set()
    pending = sorted(roots, reverse=True)
    while pending:
        module = pending.pop()
        if module in reachable:
            continue
        reachable.add(module)
        pending.extend(reversed(adjacency.get(module, [])))
    return reachable


def _graph(modules: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
    by_path = {str(item["path"]): item for item in modules}
    adjacency = {
        path: sorted(
            matched for target in item["imports"]
            if (matched := _match_module(target, by_path)) is not None
        )
        for path, item in by_path.items()
    }
    return by_path, adjacency


def _directed_paths(start: str, adjacency: dict[str, list[str]]) -> Iterator[list[str]]:
    pending = [[start]]
    emitted = 0
    while pending and emitted < MAX_FLOW_PATHS:
        path = pending.pop()
        emitted += 1
        yield path
        children = [child for child in adjacency.get(path[-1], []) if child not in path]
        if children and len(path) >= MAX_FLOW_DEPTH:
            raise FlowAnalysisLimitError(f"import depth exceeds {MAX_FLOW_DEPTH}")
        pending.extend(path + [child] for child in reversed(children))
    if pending:
        raise FlowAnalysisLimitError(f"path exploration exceeds {MAX_FLOW_PATHS}")


def _resolve_import(source: str, target: str) -> str:
    return posixpath.normpath(str(PurePosixPath(source).parent.joinpath(target)))


def _match_module(target: str, modules: dict[str, Any]) -> str | None:
    candidates = (
        target,
        *(f"{target}{suffix}" for suffix in (".js", ".cjs", ".mjs", ".ts", ".cts", ".mts")),
        *(f"{target}/index{suffix}" for suffix in (".js", ".cjs", ".mjs", ".ts")),
    )
    return next((candidate for candidate in candidates if candidate in modules), None)


def _is_executable_import(target: str) -> bool:
    suffix = PurePosixPath(target).suffix.lower()
    return not suffix or suffix in {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"}
