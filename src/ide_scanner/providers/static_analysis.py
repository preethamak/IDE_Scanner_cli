from __future__ import annotations

import hashlib
import json
import mmap
import subprocess
from pathlib import Path
from typing import Any

from ..models import Finding
from ..rules import score_finding
from .runtime import (
    YARA_RULES,
    semgrep_config_arguments,
    semgrep_diagnostic,
    semgrep_runtime_environment,
    semgrep_timeout_seconds,
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
        "--max-target-bytes", str(10 * 1024 * 1024),
        *(str(path) for path in selected),
    ]
    try:
        with semgrep_runtime_environment() as environment:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=semgrep_timeout_seconds(),
                check=False,
                env=environment,
            )
        payload = json.loads(result.stdout or "{}")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        status.update({"status": "failed", "error": str(exc)})
        return [], status
    errors = payload.get("errors") if isinstance(payload.get("errors"), list) else []
    findings = [
        finding
        for item in payload.get("results") or []
        if isinstance(item, dict)
        for finding in [_semgrep_finding(item, root, extension_id, version)]
        if finding is not None
    ]
    status.update({
        "status": "completed" if result.returncode == 0 else "failed",
        "finding_count": len(findings),
        "error_count": len(errors),
        "errors": [str(item.get("message") or item) for item in errors[:10] if isinstance(item, dict)],
        "error": result.stderr.strip()[:500] if result.returncode else "",
    })
    return findings, status


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
    selected = targets
    status["target_count"] = len(selected) if selected is not None else None
    if executable == "yara-python":
        return _run_yara_python(root, extension_id, version, status, selected)
    scan_targets = selected if selected is not None else [root]
    if not scan_targets:
        status.update({"status": "completed", "finding_count": 0, "files_analyzed": 0, "error": ""})
        return [], status
    findings: list[Finding] = []
    errors: list[str] = []
    for target in scan_targets:
        try:
            result = subprocess.run(
                [executable, "-N", str(YARA_RULES), str(target)],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"{target}: {exc}")
            continue
        if result.returncode not in {0, 1}:
            errors.append(result.stderr.strip()[:500] or f"{target}: exit {result.returncode}")
            continue
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
    status.update({
        "status": "completed" if not errors else "failed",
        "finding_count": len(findings),
        "files_analyzed": len(scan_targets) - len(errors),
        "error_count": len(errors),
        "errors": errors[:10],
        "error": errors[0] if errors else "",
    })
    return findings, status


def _run_yara_python(
    root: Path,
    extension_id: str,
    version: str,
    status: dict[str, Any],
    targets: list[Path] | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    try:
        import yara  # type: ignore[import-not-found]

        rules = yara.compile(filepath=str(YARA_RULES))
        findings: list[Finding] = []
        scanned_files = 0
        scan_targets = targets if targets is not None else list(root.rglob("*"))
        for path in scan_targets:
            if not path.is_file() or path.is_symlink():
                continue
            scanned_files += 1
            for match in rules.match(str(path), timeout=5):
                if match.rule not in _YARA_RULE_MAP:
                    continue
                rule_id, category, severity, evidence_class = _YARA_RULE_MAP[match.rule]
                rel = path.relative_to(root).as_posix()
                if _ignore_yara_match(match.rule, rel, path):
                    continue
                findings.append(_yara_finding(
                    extension_id, version, match.rule, rule_id, category, severity, evidence_class, rel
                ))
        status.update({"status": "completed", "finding_count": len(findings), "files_analyzed": scanned_files})
        return findings, status
    except Exception as exc:
        status.update({"status": "failed", "error": str(exc)})
        return [], status


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
