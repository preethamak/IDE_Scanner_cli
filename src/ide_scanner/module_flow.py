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
    import_text = _strip_js_comments(text) if analyze_imports else ""
    matches = [
        match
        for match in _IMPORT_RE.finditer(import_text)
        if _is_code_position(import_text, match.start())
    ] if analyze_imports else []
    imports = {
        _resolve_import(rel, next(value for value in match.groups() if value))
        for match in matches
    }
    optional_imports = {
        _resolve_import(rel, next(value for value in match.groups() if value))
        for match in matches
        if _is_optional_import(import_text, match.start(), match.end())
    }
    return {
        "path": rel,
        "imports": sorted(imports),
        "optional_imports": sorted(optional_imports),
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
            if target in by_path[source].get("optional_imports", []):
                continue
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


def _is_optional_import(text: str, start: int, end: int) -> bool:
    """Recognize a missing branch guarded by a local try/catch fallback."""
    before = text[max(0, start - 1024):start]
    after = text[end:min(len(text), end + 1024)]
    return bool(re.search(r"\btry\s*\{[^{}]{0,1024}$", before, re.S) and re.search(r"\bcatch\b", after))


def _is_code_position(text: str, index: int) -> bool:
    """Reject import-shaped text embedded in strings, templates, or regexes.

    Bundled extensions commonly ship parser diagnostics containing examples such
    as ``require('./module')``. The bounded import regex is intentionally
    lightweight, so a lexical guard is needed before treating a match as a
    module edge. Template literals are treated as opaque text here; imports in
    interpolation are not static module declarations and should not affect
    coverage.
    """
    state = "normal"
    regex_class = False
    output: list[str] = []
    cursor = 0
    while cursor < index:
        char = text[cursor]
        if state == "normal":
            if char in {"'", '"'}:
                state = char
            elif char == "`":
                state = "template"
            elif char == "/" and _looks_like_regex_start(output):
                state = "regex"
                regex_class = False
            output.append(char)
            cursor += 1
            continue
        if state in {"'", '"'}:
            if char == "\\":
                cursor += 2
                output.extend((" ", " "))
                continue
            if char == state:
                state = "normal"
            output.append(" ")
            cursor += 1
            continue
        if state == "template":
            if char == "\\":
                cursor += 2
                output.extend((" ", " "))
                continue
            if char == "`":
                state = "normal"
            output.append(" ")
            cursor += 1
            continue
        if char == "\\":
            cursor += 2
            output.extend((" ", " "))
            continue
        if char == "[":
            regex_class = True
        elif char == "]":
            regex_class = False
        elif char == "/" and not regex_class and _looks_like_regex_end(text, cursor):
            state = "normal"
        output.append(" ")
        cursor += 1
    return state == "normal"


def _looks_like_regex_end(text: str, index: int) -> bool:
    """Use a small delimiter check so malformed examples do not poison the scan."""
    match = re.match(r"[dgimsuvy]*", text[index + 1:])
    end = index + 1 + len(match.group(0)) if match else index + 1
    next_char = text[end] if end < len(text) else ""
    return not next_char or next_char.isspace() or next_char in ";,)]}(:?&|.+-*%"


def _match_module(target: str, modules: dict[str, Any]) -> str | None:
    candidates = (
        target,
        *(f"{target}{suffix}" for suffix in (".js", ".cjs", ".mjs", ".ts", ".cts", ".mts")),
        *(f"{target}/index{suffix}" for suffix in (".js", ".cjs", ".mjs", ".ts")),
    )
    return next((candidate for candidate in candidates if candidate in modules), None)


def _is_executable_import(target: str) -> bool:
    suffix = PurePosixPath(target).suffix.lower()
    if target.lower().endswith(".d.ts"):
        return False
    return not suffix or suffix in {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"}


def _strip_js_comments(text: str) -> str:
    """Remove JavaScript comments while preserving quoted source positions.

    The module graph is intentionally regex-based and bounded, but applying it
    directly to source makes documentation examples such as
    ``// require('./optional')`` look like executable edges. This small lexer
    removes line/block comments, preserves ordinary quoted strings, and masks
    template-literal text so real imports keep their original offsets and
    spelling without treating generated documentation as code.
    """
    output: list[str] = []
    index = 0
    state = "normal"
    regex_class = False
    length = len(text)
    while index < length:
        char = text[index]
        next_char = text[index + 1] if index + 1 < length else ""
        if state == "normal":
            if char == "/" and next_char == "/":
                output.extend((" ", " "))
                index += 2
                state = "line-comment"
                continue
            if char == "/" and next_char == "*":
                output.extend((" ", " "))
                index += 2
                state = "block-comment"
                continue
            if char == "/" and _looks_like_regex_start(output):
                output.append(char)
                state = "regex"
                regex_class = False
                index += 1
                continue
            if char == "`":
                output.append(" ")
                state = "template"
                index += 1
                continue
            output.append(char)
            if char in {"'", '"'}:
                state = char
            index += 1
            continue
        if state == "line-comment":
            if char in "\r\n":
                output.append(char)
                state = "normal"
            else:
                output.append(" ")
            index += 1
            continue
        if state == "block-comment":
            if char == "*" and next_char == "/":
                output.extend((" ", " "))
                index += 2
                state = "normal"
            else:
                output.append(char if char in "\r\n" else " ")
                index += 1
            continue

        if state == "template":
            if char == "\\" and index + 1 < length:
                output.extend((" ", "\n" if text[index + 1] in "\r\n" else " "))
                index += 2
                continue
            if char == "`":
                output.append(" ")
                state = "normal"
            else:
                output.append(char if char in "\r\n" else " ")
            index += 1
            continue

        if state == "regex":
            output.append(char)
            if char == "\\" and index + 1 < length:
                output.append(text[index + 1])
                index += 2
                continue
            if char == "[":
                regex_class = True
            elif char == "]":
                regex_class = False
            elif char == "/" and not regex_class:
                state = "normal"
            index += 1
            continue

        # Ordinary quoted strings are copied verbatim. Escaped delimiters must
        # not terminate the state; this is sufficient for the import forms
        # recognized above without attempting JavaScript parsing.
        output.append(char)
        if char == "\\" and index + 1 < length:
            output.append(text[index + 1])
            index += 2
            continue
        if char == state:
            state = "normal"
        index += 1
    return "".join(output)


def _looks_like_regex_start(output: list[str]) -> bool:
    """Recognize the common expression positions where ``/`` starts a regex."""
    previous = next((char for char in reversed(output) if not char.isspace()), "")
    if not previous or previous in "=([{!,:;?&|+-*%^~<>":
        return True
    keyword = []
    for char in reversed(output):
        if char.isalpha():
            keyword.append(char)
        else:
            break
    return "".join(reversed(keyword)) in {"return", "case", "throw", "else", "do", "yield", "await"}
