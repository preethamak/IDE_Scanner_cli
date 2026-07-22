from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..models import Finding
from ..rules import score_finding

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SEMGREP_RULES = _PROJECT_ROOT / "rules" / "semgrep"
_YARA_RULES = _PROJECT_ROOT / "rules" / "yara" / "ide-scanner.yar"
_YARA_RULE_MAP = {
    "ide_scanner_unicode_evasion": ("unicode-evasion", "code", "MEDIUM", "weak"),
    # YARA can only establish that markers co-occur in one file; it cannot prove
    # that decoded data reaches execution. Keep it as context. The Semgrep taint
    # rule is responsible for the verdict-driving source-to-sink claim.
    "ide_scanner_encoded_dynamic_execution": ("encoded-dynamic-execution", "code", "HIGH", "weak"),
    "ide_scanner_embedded_pe": ("embedded-pe-artifact", "artifact", "MEDIUM", "provenance"),
}

_YARA_NON_EXECUTABLE_SUFFIXES = {".map", ".md", ".txt", ".json", ".jsonc"}


def _ignore_yara_match(rule_name: str, rel: str) -> bool:
    suffix = Path(rel).suffix.lower()
    if rule_name == "ide_scanner_embedded_pe" and suffix in _YARA_NON_EXECUTABLE_SUFFIXES:
        return True
    return False


def run_static_providers(root: Path, extension_id: str, version: str) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    statuses: dict[str, Any] = {}
    semgrep_findings, statuses["semgrep"] = _run_semgrep(root, extension_id, version)
    yara_findings, statuses["yara"] = _run_yara(root, extension_id, version)
    findings.extend(semgrep_findings)
    findings.extend(yara_findings)
    return findings, statuses


def _run_semgrep(root: Path, extension_id: str, version: str) -> tuple[list[Finding], dict[str, Any]]:
    executable = shutil.which("semgrep")
    status = _provider_status("semgrep", executable, _SEMGREP_RULES)
    if not executable or not _SEMGREP_RULES.is_dir():
        return [], status
    command = [
        executable,
        "scan",
        "--config", str(_SEMGREP_RULES),
        "--json",
        "--metrics", "off",
        "--disable-version-check",
        "--no-git-ignore",
        "--max-target-bytes", str(10 * 1024 * 1024),
        str(root),
    ]
    try:
        env = os.environ.copy()
        env["SEMGREP_SETTINGS_FILE"] = str(Path(tempfile.gettempdir()) / "ide-scanner-semgrep-settings.yml")
        env["SEMGREP_LOG_FILE"] = str(Path(tempfile.gettempdir()) / "ide-scanner-semgrep.log")
        env["SEMGREP_SEND_METRICS"] = "off"
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False, env=env)
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


def _run_yara(root: Path, extension_id: str, version: str) -> tuple[list[Finding], dict[str, Any]]:
    executable = shutil.which("yara")
    python_available = importlib.util.find_spec("yara") is not None
    status = _provider_status("yara", executable or ("yara-python" if python_available else None), _YARA_RULES)
    if not _YARA_RULES.is_file():
        return [], status
    if not executable and python_available:
        return _run_yara_python(root, extension_id, version, status)
    if not executable:
        return [], status
    try:
        result = subprocess.run(
            [executable, "-N", "-r", str(_YARA_RULES), str(root)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        status.update({"status": "failed", "error": str(exc)})
        return [], status
    findings: list[Finding] = []
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
        if _ignore_yara_match(rule_name, rel):
            continue
        findings.append(_provider_finding(
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
        ))
    status.update({
        "status": "completed" if result.returncode in {0, 1} else "failed",
        "finding_count": len(findings),
        "error": result.stderr.strip()[:500],
    })
    return findings, status


def _run_yara_python(
    root: Path,
    extension_id: str,
    version: str,
    status: dict[str, Any],
) -> tuple[list[Finding], dict[str, Any]]:
    try:
        import yara  # type: ignore[import-not-found]

        rules = yara.compile(filepath=str(_YARA_RULES))
        findings: list[Finding] = []
        scanned_files = 0
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            scanned_files += 1
            for match in rules.match(str(path), timeout=5):
                if match.rule not in _YARA_RULE_MAP:
                    continue
                rule_id, category, severity, evidence_class = _YARA_RULE_MAP[match.rule]
                rel = path.relative_to(root).as_posix()
                if _ignore_yara_match(match.rule, rel):
                    continue
                findings.append(_provider_finding(
                    extension_id,
                    version,
                    rule_id,
                    category,
                    severity,
                    0.8 if evidence_class == "correlated" else 0.68,
                    f"YARA rule {match.rule} matched {rel}.",
                    [rel],
                    "Inspect the matched bytes and validate the rule provenance before taking action.",
                    {"provider": "yara", "provider_rule_id": match.rule, "evidence_class": evidence_class},
                ))
        status.update({"status": "completed", "finding_count": len(findings), "files_analyzed": scanned_files})
        return findings, status
    except Exception as exc:
        status.update({"status": "failed", "error": str(exc)})
        return [], status


def _provider_status(name: str, executable: str | None, rules_path: Path) -> dict[str, Any]:
    ruleset_hash = ""
    if rules_path.is_file():
        ruleset_hash = hashlib.sha256(rules_path.read_bytes()).hexdigest()
    elif rules_path.is_dir():
        digest = hashlib.sha256()
        for rule in sorted(rules_path.rglob("*")):
            if rule.is_file():
                digest.update(rule.relative_to(rules_path).as_posix().encode("utf-8"))
                digest.update(rule.read_bytes())
        ruleset_hash = digest.hexdigest()
    return {
        "provider": name,
        "status": "available" if executable else "unavailable",
        "executable": executable or "",
        "ruleset_hash": ruleset_hash,
        "required": False,
    }


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
