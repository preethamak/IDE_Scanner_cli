from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

JS_AST_EXTS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_WALKER_PATH = Path(__file__).parent / "js_ast" / "walker.js"
# Deep analysis reads generated entrypoints up to the scanner's 64 MiB text
# boundary. Acorn can require roughly 1.5 GiB and about a minute for a bundle
# near that limit on a single CPU. Keep both limits fixed and report them in
# provider metadata so the coverage boundary is reproducible.
JS_AST_TIMEOUT_SECONDS = 90
JS_AST_MAX_OLD_SPACE_MB = 2048
JS_AST_TIMEOUT_ATTEMPTS = 2

_node_available: bool | None = None


def node_available() -> bool:
    global _node_available
    if _node_available is None:
        _node_available = shutil.which("node") is not None
    return _node_available


def analyze_js_source_status(rel: str, text: str) -> tuple[list[dict[str, Any]], str]:
    """Run the vendored acorn-based walker over one JS/TS source blob.

    Returns ``(findings, status)`` where ``status`` is one of:
    ``ok`` (walker parsed the file and produced structured output),
    ``unparsed`` (walker ran cleanly but acorn could not parse the source --
    the vendored parser only understands plain JavaScript, so TypeScript/JSX
    source and syntactically invalid input land here; the raw-text rule layer
    still covers these files, so this is a disclosed tool limitation, not an
    analyzer failure), ``node-missing`` (no node runtime), ``timeout`` (walker
    exceeded the time budget), ``error`` (spawn/OS error), or ``malformed``
    (walker crashed or its output could not be parsed). Callers use the status
    to report truthful provider coverage instead of silently treating every
    failure as "no findings"."""
    if not node_available():
        return [], "node-missing"
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=Path(rel).suffix or ".js", delete=False) as handle:
            handle.write(text)
            source_path = handle.name
        try:
            command = ["node", f"--max-old-space-size={JS_AST_MAX_OLD_SPACE_MB}", str(_WALKER_PATH), source_path]
            for attempt in range(JS_AST_TIMEOUT_ATTEMPTS):
                try:
                    proc = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=JS_AST_TIMEOUT_SECONDS,
                    )
                    break
                except subprocess.TimeoutExpired:
                    if attempt + 1 == JS_AST_TIMEOUT_ATTEMPTS:
                        return [], "timeout"
        finally:
            Path(source_path).unlink(missing_ok=True)
    except (OSError, subprocess.SubprocessError):
        return [], "error"

    if proc.returncode != 0 and not proc.stdout:
        # The walker exits non-zero with a diagnostic on stderr for genuine
        # parse errors; acorn recovers from most malformed input, so a hard
        # failure here is a material analyzer failure, not benign.
        return [], "malformed"
    try:
        payload = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return [], "malformed"
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return [], "malformed"
    # The walker exits 0 with an ``error`` field for two distinct cases,
    # disambiguated by ``kind``:
    #   - kind == "unparsed": acorn could not parse the source. Expected for
    #     TypeScript/JSX (the vendored parser is plain-JS only) and for
    #     malformed input. The AST layer analyzed nothing, but the raw-text
    #     rule layer still covers the file, so this is a disclosed limitation.
    #   - kind == "walk-error": parsing succeeded but traversal crashed. That
    #     is a genuine analyzer failure and must fail closed as ``malformed``.
    # Any other error shape (missing/unknown kind) is treated conservatively as
    # malformed rather than silently trusted.
    if payload.get("error"):
        kind = payload.get("kind")
        if kind == "unparsed":
            return [], "unparsed"
        return [], "malformed"
    return [item for item in findings if isinstance(item, dict) and item.get("rule")], "ok"


def analyze_js_source(rel: str, text: str) -> list[dict[str, Any]]:
    """Backwards-compatible wrapper returning only findings."""
    findings, _status = analyze_js_source_status(rel, text)
    return findings
