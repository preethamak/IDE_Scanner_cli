"""Evidence location extraction shared by CLI output and report bundles."""

from __future__ import annotations

from typing import Any


def location_from_finding(finding: Any) -> dict[str, Any]:
    """Best-effort primary code location for a finding.

    Prefers ``file_refs`` entries (optionally ``path:line``), then explicit
    ``file``/``line`` keys on the finding, then the raw evidence payload.
    Never raises: an unusable location yields ``{"file": None, "line": None}``.
    """
    if isinstance(finding, dict):
        file_refs = finding.get("file_refs")
        evidence = finding.get("evidence")
        direct_file = finding.get("file")
        direct_line = finding.get("line")
    else:
        file_refs = getattr(finding, "file_refs", None)
        evidence = getattr(finding, "evidence", None)
        direct_file = getattr(finding, "file", None)
        direct_line = getattr(finding, "line", None)

    fallback_line = int(direct_line) if _is_int(direct_line) else None
    if fallback_line is None and isinstance(evidence, dict) and _is_int(evidence.get("line")):
        fallback_line = int(evidence["line"])

    for ref in file_refs or []:
        if not isinstance(ref, str) or not ref.strip():
            continue
        path, line = _split_path_line(ref.strip())
        return {"file": path, "line": line if line is not None else fallback_line}

    if isinstance(evidence, dict):
        for key in ("primary_location", "location"):
            candidate = evidence.get(key)
            if isinstance(candidate, dict):
                path = candidate.get("file") or candidate.get("path")
                line = candidate.get("line")
                if path:
                    return {"file": str(path), "line": int(line) if _is_int(line) else None}
        path = evidence.get("file") or evidence.get("path")
        if isinstance(path, str) and path.strip():
            resolved, line = _split_path_line(path.strip())
            if line is None and _is_int(evidence.get("line")):
                line = int(evidence["line"])
            return {"file": resolved, "line": line}

    if isinstance(direct_file, str) and direct_file.strip():
        path, line = _split_path_line(direct_file.strip())
        if line is None and _is_int(direct_line):
            line = int(direct_line)
        return {"file": path, "line": line}

    return {"file": None, "line": None}


def _split_path_line(ref: str) -> tuple[str, int | None]:
    if ref.startswith(("http://", "https://")):
        return ref, None
    if ":" in ref:
        path, _, suffix = ref.rpartition(":")
        if path and _is_int(suffix):
            return path, int(suffix)
    return ref, None


def _is_int(value: Any) -> bool:
    try:
        int(value)
    except (TypeError, ValueError):
        return False
    return True
