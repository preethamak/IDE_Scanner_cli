from __future__ import annotations

import hashlib
import json
import mmap
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from ..models import Finding
from ..rules import score_finding
from .runtime import (
    SEMGREP_RULES,
    SEMGREP_MAX_TARGET_BYTES,
    SEMGREP_MEMORY_LIMIT_MB,
    SEMGREP_RULE_TIMEOUT_SECONDS,
    PROVIDER_FILE_SIZE_LIMIT_MB,
    PROVIDER_MEMORY_LIMIT_MB,
    YARA_RULES,
    semgrep_config_arguments,
    semgrep_diagnostic,
    semgrep_runtime_environment,
    semgrep_timeout_seconds,
    run_bounded_process,
    yara_diagnostic,
)

_YARA_RULE_MAP = {
    "ide_scanner_unicode_evasion": ("unicode-evasion", "code", "MEDIUM", "weak"),
    # YARA can only establish that markers co-occur in one file; it cannot prove
    # that decoded data reaches execution. Keep it as context. The Semgrep taint
    # rule is responsible for the verdict-driving source-to-sink claim.
    "ide_scanner_encoded_dynamic_execution": ("encoded-dynamic-execution", "code", "HIGH", "weak"),
    "ide_scanner_embedded_pe": ("embedded-pe-artifact", "artifact", "MEDIUM", "provenance"),
}

_YARA_NON_EXECUTABLE_SUFFIXES = {".map", ".md", ".txt", ".json", ".jsonc"}
_SEMGREP_RULE_IDS = {
    "credential-dataflow-to-network",
    "decoded-payload-execution",
    "untrusted-workspace-input-to-process",
    "webview-message-to-process",
}


def _ignore_yara_match(rule_name: str, rel: str, path: Path) -> bool:
    suffix = Path(rel).suffix.lower()
    if rule_name in {"ide_scanner_unicode_evasion", "ide_scanner_encoded_dynamic_execution"}:
        return suffix not in {".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ps1", ".py", ".sh", ".ts", ".tsx"}
    if rule_name == "ide_scanner_embedded_pe":
        if suffix in _YARA_NON_EXECUTABLE_SUFFIXES:
            return True
        return not _has_valid_embedded_pe(path)
    return False


def run_static_providers(
    root: Path,
    extension_id: str,
    version: str,
    *,
    targets: dict[str, list[str]] | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    statuses: dict[str, Any] = {}
    semgrep_findings, statuses["semgrep"] = _run_semgrep(
        root, extension_id, version, _resolved_targets(root, targets, "semgrep")
    )
    yara_findings, statuses["yara"] = _run_yara(
        root, extension_id, version, _resolved_targets(root, targets, "yara")
    )
    findings.extend(semgrep_findings)
    findings.extend(yara_findings)
    return findings, statuses


def _run_semgrep(
    root: Path,
    extension_id: str,
    version: str,
    targets: list[Path] | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    status = semgrep_diagnostic()
    executable = str(status["executable"])
    if status["status"] != "available":
        return [], status
    status.update({
        "isolation": "subprocess",
        "memory_limit_mb": SEMGREP_MEMORY_LIMIT_MB,
        "memory_limit_enforcement": "semgrep_per_file",
        "file_size_limit_mb": PROVIDER_FILE_SIZE_LIMIT_MB,
    })
    selected = targets if targets is not None else [root]
    status["target_count"] = len(selected)
    if not selected:
        status.update({"status": "completed", "finding_count": 0, "error_count": 0, "errors": [], "error": ""})
        return [], status
    command = [
        executable,
        "scan",
        *semgrep_config_arguments(),
        "--json",
        "--metrics", "off",
        "--disable-version-check",
        "--no-git-ignore",
        "--jobs", "1",
        "--max-memory", str(SEMGREP_MEMORY_LIMIT_MB),
        "--timeout", str(SEMGREP_RULE_TIMEOUT_SECONDS),
        "--max-target-bytes", str(SEMGREP_MAX_TARGET_BYTES),
        *(str(path) for path in selected),
    ]
    try:
        with semgrep_runtime_environment() as environment:
            result = run_bounded_process(
                command,
                timeout=semgrep_timeout_seconds(),
                env=environment,
                # RLIMIT_AS is incompatible with semgrep-core's virtual-memory
                # reservation. Semgrep enforces --max-memory per analyzed file.
                memory_limit_mb=None,
                file_size_limit_mb=PROVIDER_FILE_SIZE_LIMIT_MB,
            )
        payload = json.loads(result.stdout or "{}")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        status.update({"status": "failed", "error": str(exc)})
        return [], status
    errors = payload.get("errors") if isinstance(payload.get("errors"), list) else []
    unsupported = [
        item for item in errors
        if isinstance(item, dict) and _semgrep_unsupported_target_error(item)
    ]
    blocking_errors = [
        item for item in errors
        if not (isinstance(item, dict) and _semgrep_unsupported_target_error(item))
    ]
    findings = [
        finding
        for item in payload.get("results") or []
        if isinstance(item, dict)
        for finding in [_semgrep_finding(item, root, extension_id, version)]
        if finding is not None
    ]
    provider_completed = result.returncode == 0 and not blocking_errors
    status.update({
        "status": "completed" if provider_completed else "failed",
        "finding_count": len(findings),
        "error_count": len(blocking_errors),
        "errors": [
            _semgrep_diagnostic_text(str(item.get("message") or item), root)
            for item in blocking_errors[:10]
            if isinstance(item, dict)
        ],
        "unsupported_parse_error_count": len(unsupported),
        "unsupported_targets": [
            _semgrep_diagnostic_text(str(item.get("message") or item), root)
            for item in unsupported[:50]
        ],
        "error": (
            _semgrep_diagnostic_text(result.stderr, root)
            or (
                f"Semgrep reported {len(blocking_errors)} target analysis error(s)"
                if blocking_errors else ""
            )
        ) if not provider_completed else "",
    })
    return findings, status


def _semgrep_diagnostic_text(value: str, root: Path) -> str:
    """Bound provider diagnostics and remove machine-specific path prefixes."""
    text = value.strip().replace(str(root.resolve()), "<artifact>")
    text = text.replace(str(SEMGREP_RULES.resolve()), "<rules>")
    for rule_id in _SEMGREP_RULE_IDS:
        text = re.sub(
            rf"(?:[A-Za-z0-9_-]+\.)+{re.escape(rule_id)}",
            rule_id,
            text,
        )
    return text[:500]


def _semgrep_unsupported_target_error(item: dict[str, Any]) -> bool:
    """Identify parser incompatibility, not resource or execution failure."""
    error_type = str(item.get("type") or "").lower()
    message = str(item.get("message") or "").lower()
    return (
        "parse error" in error_type
        or "syntax error" in error_type
        or message.startswith("syntax error at line ")
    )


def _semgrep_finding(item: dict[str, Any], root: Path, extension_id: str, version: str) -> Finding | None:
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    provider_rule = str(item.get("check_id") or "").split(".")[-1]
    if not provider_rule:
        return None
    severity = str(metadata.get("ide_scanner_severity") or extra.get("severity") or "MEDIUM").upper()
    if severity not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        severity = "MEDIUM"
    evidence_class = str(metadata.get("ide_scanner_evidence_class") or "weak")
    category = str(metadata.get("ide_scanner_category") or "code")
    path = Path(str(item.get("path") or ""))
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        rel = path.as_posix()
    start = item.get("start") if isinstance(item.get("start"), dict) else {}
    end = item.get("end") if isinstance(item.get("end"), dict) else {}
    summary = str(extra.get("message") or provider_rule)
    confidence = 0.86 if evidence_class == "correlated" else 0.72
    return _provider_finding(
        extension_id,
        version,
        provider_rule,
        category,
        severity,
        confidence,
        summary,
        [rel] if rel else [],
        "Review the reported source-to-sink path and confirm the behavior is required and user-authorized.",
        {
            "provider": "semgrep",
            "provider_rule_id": str(item.get("check_id") or provider_rule),
            "evidence_class": evidence_class,
            "location": {
                "line_start": start.get("line"),
                "line_end": end.get("line"),
            },
        },
    )


def _run_yara(
    root: Path,
    extension_id: str,
    version: str,
    targets: list[Path] | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    status = yara_diagnostic()
    executable = str(status["executable"])
    if status["status"] != "available":
        return [], status
    status.update({
        "isolation": "subprocess",
        "memory_limit_mb": PROVIDER_MEMORY_LIMIT_MB,
        "file_size_limit_mb": PROVIDER_FILE_SIZE_LIMIT_MB,
    })
    selected = targets
    status["target_count"] = len(selected) if selected is not None else None
    if executable == "yara-python":
        return _run_yara_python(root, extension_id, version, status, selected)
    if selected == []:
        status.update({"status": "completed", "finding_count": 0, "files_analyzed": 0, "error": ""})
        return [], status
    findings: list[Finding] = []
    target_file: Path | None = None
    try:
        if selected is None:
            scan_options = ["-r"]
            scan_target = root
        else:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", prefix="ide-scanner-native-yara-targets-", delete=False
            ) as handle:
                target_file = Path(handle.name)
                for path in selected:
                    resolved = str(path.resolve())
                    if "\n" in resolved or "\r" in resolved:
                        raise ValueError("YARA target path cannot contain a line break")
                    handle.write(resolved + "\n")
            scan_options = ["--scan-list"]
            scan_target = target_file
        result = run_bounded_process(
            [executable, "-N", *scan_options, str(YARA_RULES), str(scan_target)],
            timeout=120,
            memory_limit_mb=PROVIDER_MEMORY_LIMIT_MB,
            file_size_limit_mb=PROVIDER_FILE_SIZE_LIMIT_MB,
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        status.update({"status": "failed", "error_count": 1, "error": str(exc)})
        return [], status
    finally:
        if target_file is not None:
            target_file.unlink(missing_ok=True)
    if result.returncode in {0, 1}:
        for line in result.stdout.splitlines():
            rule_name, separator, matched_path = line.partition(" ")
            if not separator or rule_name not in _YARA_RULE_MAP:
                continue
            rule_id, category, severity, evidence_class = _YARA_RULE_MAP[rule_name]
            path = Path(matched_path.strip())
            try:
                rel = path.resolve().relative_to(root.resolve()).as_posix()
            except (OSError, ValueError):
                rel = path.as_posix()
            if _ignore_yara_match(rule_name, rel, path):
                continue
            findings.append(_yara_finding(
                extension_id, version, rule_name, rule_id, category, severity, evidence_class, rel
            ))
    error = result.stderr.strip()[:500] if result.returncode not in {0, 1} else ""
    status.update({
        "status": "completed" if result.returncode in {0, 1} else "failed",
        "finding_count": len(findings),
        "files_analyzed": len(selected) if selected is not None else None,
        "error_count": 0 if not error else 1,
        "error": error,
    })
    return findings, status


def _run_yara_python(
    root: Path,
    extension_id: str,
    version: str,
    status: dict[str, Any],
    targets: list[Path] | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    target_paths = targets if targets is not None else [path for path in root.rglob("*") if path.is_file()]
    target_file = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="ide-scanner-yara-targets-", delete=False) as handle:
            target_file = Path(handle.name)
            for path in target_paths:
                if not path.is_file() or path.is_symlink():
                    continue
                try:
                    handle.write(path.resolve().relative_to(root.resolve()).as_posix() + "\n")
                except (OSError, ValueError):
                    continue
        result = run_bounded_process(
            [
                sys.executable,
                "-m",
                "ide_scanner.providers.yara_worker",
                "--root", str(root),
                "--rules", str(YARA_RULES),
                "--targets", str(target_file),
            ],
            timeout=120,
            memory_limit_mb=PROVIDER_MEMORY_LIMIT_MB,
            file_size_limit_mb=PROVIDER_FILE_SIZE_LIMIT_MB,
        )
        payload = json.loads(result.stdout or "{}")
        findings: list[Finding] = []
        for match in payload.get("matches") or []:
            if not isinstance(match, dict):
                continue
            rule_name = str(match.get("rule") or "")
            rel = str(match.get("path") or "")
            if rule_name not in _YARA_RULE_MAP or not rel:
                continue
            path = root.joinpath(*rel.split("/"))
            rule_id, category, severity, evidence_class = _YARA_RULE_MAP[rule_name]
            if _ignore_yara_match(rule_name, rel, path):
                continue
            findings.append(_yara_finding(
                extension_id, version, rule_name, rule_id, category, severity, evidence_class, rel
            ))
        errors = payload.get("errors") if isinstance(payload.get("errors"), list) else []
        completed = result.returncode == 0 and not errors and not payload.get("truncated")
        status.update({
            "status": "completed" if completed else "failed",
            "finding_count": len(findings),
            "files_analyzed": int(payload.get("files_analyzed") or 0),
            "error_count": len(errors),
            "errors": errors[:10],
            "error": "" if completed else _yara_worker_error(result, errors, bool(payload.get("truncated"))),
            "isolation": "subprocess",
            "memory_limit_mb": PROVIDER_MEMORY_LIMIT_MB,
            "file_size_limit_mb": PROVIDER_FILE_SIZE_LIMIT_MB,
        })
        return findings, status
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError) as exc:
        status.update({
            "status": "failed",
            "error_count": 1,
            "error": str(exc)[:500],
            "isolation": "subprocess",
            "memory_limit_mb": PROVIDER_MEMORY_LIMIT_MB,
            "file_size_limit_mb": PROVIDER_FILE_SIZE_LIMIT_MB,
        })
        return [], status
    finally:
        if target_file is not None:
            target_file.unlink(missing_ok=True)


def _yara_worker_error(result: subprocess.CompletedProcess[str], errors: list[Any], truncated: bool) -> str:
    if truncated:
        return "YARA worker exceeded its bounded match output; results are incomplete."
    if errors:
        first = errors[0] if isinstance(errors[0], dict) else {"error": str(errors[0])}
        return str(first.get("error") or "YARA worker reported an artifact error.")[:500]
    return (result.stderr.strip() or f"YARA worker exited with status {result.returncode}.")[:500]


def _resolved_targets(
    root: Path,
    targets: dict[str, list[str]] | None,
    provider: str,
) -> list[Path] | None:
    if targets is None:
        return None
    resolved_root = root.resolve()
    selected: list[Path] = []
    for rel in targets.get(provider, []):
        candidate = root.joinpath(*str(rel).split("/"))
        try:
            resolved = candidate.resolve()
            resolved.relative_to(resolved_root)
        except (OSError, ValueError):
            continue
        if resolved.is_file() and not candidate.is_symlink():
            selected.append(resolved)
    return selected


def _has_valid_embedded_pe(path: Path) -> bool:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size < 68:
            return False
        with path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            start = 1
            while True:
                base = data.find(b"MZ", start)
                if base < 0:
                    return False
                if base + 64 <= len(data):
                    pe_offset = int.from_bytes(data[base + 60:base + 64], "little")
                    header = base + pe_offset
                    if pe_offset >= 64 and header + 4 <= len(data) and data[header:header + 4] == b"PE\0\0":
                        return True
                start = base + 2
    except (OSError, ValueError):
        return False


def _yara_finding(
    extension_id: str,
    version: str,
    rule_name: str,
    rule_id: str,
    category: str,
    severity: str,
    evidence_class: str,
    rel: str,
) -> Finding:
    return _provider_finding(
        extension_id,
        version,
        rule_id,
        category,
        severity,
        0.8 if evidence_class == "correlated" else 0.68,
        f"YARA rule {rule_name} matched {rel}.",
        [rel],
        "Inspect the matched bytes and validate the rule provenance before taking action.",
        {"provider": "yara", "provider_rule_id": rule_name, "evidence_class": evidence_class},
    )


def _provider_finding(
    extension_id: str,
    version: str,
    rule_id: str,
    category: str,
    severity: str,
    confidence: float,
    summary: str,
    file_refs: list[str],
    recommendation: str,
    evidence: dict[str, Any],
) -> Finding:
    payload = f"{extension_id}:{version}:{rule_id}:{','.join(file_refs)}:{summary}"
    return Finding(
        finding_id=hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16],
        extension_id=extension_id,
        version=version,
        rule_id=rule_id,
        category=category,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,
        score=score_finding(severity, confidence),
        evidence_type="static-provider",
        evidence_summary=summary,
        file_refs=file_refs,
        recommendation=recommendation,
        evidence=evidence,
    )
