from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .ast_analyzer import (
    JS_AST_EXTS,
    JS_AST_MAX_OLD_SPACE_MB,
    JS_AST_TIMEOUT_ATTEMPTS,
    JS_AST_TIMEOUT_SECONDS,
    analyze_js_source_status,
    node_available,
)
from .classification_policy import (
    POLICY_VERSION,
    effective_finding_severity,
    finding_actionability,
    is_decision_relevant,
    is_review_relevant,
)
from .discovery import discover_from_path, discover_local_installations
from .jsonc import loads_jsonc
from .models import ExtensionReport, Finding
from .public_outcomes import apply_public_assessment
from .rule_registry import RULESET_VERSION
from .posture import scan_posture, summarize_posture
from .providers import run_static_providers
from .registry import (
    MarketplaceDownloadError,
    _degzip_if_needed,
    download_marketplace_vsix,
    enrich_registry,
    parse_marketplace_reference,
)
from .rules import (
    CODE_RULES,
    DESTRUCTIVE_RE,
    DOWNLOAD_RE,
    ENCODE_ARCHIVE_RE,
    FILE_READ_RE,
    FILE_WRITE_RE,
    NETWORK_SINK_RE,
    SECRET_PATTERNS,
    rank_severity,
    score_finding,
)

TEXT_EXTS = {
    ".cjs",
    ".cts",
    ".js",
    ".json",
    ".jsonc",
    ".jsx",
    ".mjs",
    ".mts",
    ".ps1",
    ".py",
    ".sh",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
    ".html",
    ".htm",
}
EXEC_TEXT_EXTS = {".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ps1", ".py", ".sh", ".ts", ".tsx"}
BINARY_RISK_EXTS = {".dll", ".dylib", ".exe", ".node", ".so"}
PACKED_RISK_EXTS = {".7z", ".asar", ".gz", ".jar", ".rar", ".tar", ".tgz", ".war", ".zip"}
SKIP_DIRS = {".git", ".hg", ".svn"}
MAX_TEXT_BYTES = 64 * 1024 * 1024
MAX_SOURCE_PREVIEW_BYTES = 200 * 1024
MAX_SOURCE_PREVIEWS = 40
GENERATED_BLOB_BYTES = 10 * 1024 * 1024
# Generated webpack/esbuild output can be substantially smaller than 1 MiB.
# Treat a long, nearly line-free JavaScript artifact as generated once it is
# large enough that character proximity no longer represents source locality.
MINIFIED_BLOB_BYTES = 256 * 1024
MAX_ARCHIVE_FILES = 100_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_COMPRESSION_RATIO = 100
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CONFIRMED_RULES = {"known-bad-artifact", "marketplace-removed-malware", "malicious-npm-dependency", "trusted-threat-feed-hit"}
OBSERVED_RULES = {
    "observed-secret-exfil",
    "observed-download-execute",
    "observed-persistence",
    "observed-destructive-behavior",
    "observed-process-exec",
    "observed-filesystem-write",
}
CORRELATED_RULES = {
    "agent-data-exfil-chain",
    "credential-exfiltration-chain",
    "destructive-transfer-chain",
    "download-and-execute",
    "install-download-execute",
    "install-secret-access",
    "install-shell-obfuscation",
    "obfuscation-execution-network",
    "persistence-chain",
    "supply-chain-dropper-chain",
}
BLOCKING_CORRELATED_RULES = CORRELATED_RULES - {"download-and-execute"}
BLOCKING_OBSERVED_RULES = {
    "observed-destructive-behavior",
    "observed-download-execute",
    "observed-persistence",
    "observed-secret-exfil",
}
DOWNLOAD_EXECUTE_CREDENTIAL_SIGNALS = {
    "credential-command-control",
    "credential-config-key",
    "credential-config-update",
    "credential-global-state-key",
    "credential-global-state-storage",
    "credential-inputbox-prompt",
}
CAPABILITY_RULES = {
    "agent-filesystem-tool",
    "agent-network-tool",
    "agent-prompt-injection-sink",
    "agent-shell-tool",
    "agentic-tooling",
    "ast-dynamic-call-target",
    "ast-bracket-notation-sensitive-access",
    "ast-constructed-dynamic-argument",
    "broad-activation",
    "credential-command-execution",
    "credential-command-registration",
    "credential-config-key",
    "credential-config-update",
    "credential-global-state-key",
    "credential-global-state-storage",
    "credential-inputbox-prompt",
    "dynamic-shell-execution",
    "lifecycle-script",
    "mcp-server-command",
    "native-or-packed-artifact",
    "powerful-ide-contribution",
    "sensitive-activation",
    "startup-activation",
    "untrusted-input-execution",
    "webview-csp-missing",
    "webview-csp-unsafe-directive",
}
DEPENDENCY_RULES = {"mutable-dependency-source", "unpinned-dependency", "vulnerable-npm-dependency"}
PROVENANCE_RULES = {"marketplace-removed-package", "packed-artifact", "source-vsix-diff-unexplained", "binary-without-origin"}
POSTURE_RULES = {"dangerous-github-workflow", "repo-binary-artifacts", "workflow-token-permissions-broad", "entrypoint-ast-unparsed"}
REPUTATION_RULES = {
    "marketplace-extension-not-found",
    "marketplace-low-install-count",
    "marketplace-low-rating",
    "marketplace-name-impersonation",
    "marketplace-stale-extension",
    "marketplace-unverified-publisher",
    "marketplace-verified-publisher",
    "install-rating-mismatch",
    "repo-archived",
    "repo-maintained",
    "repo-stale",
    "repo-url-missing",
    "security-policy-missing",
    "license-missing",
}
EXPOSURE_RULES = {
    "agent-sensitive-data-near-network",
    "credential-command-control",
    "credential-command-execution",
    "credential-command-registration",
    "credential-config-key",
    "credential-config-update",
    "credential-dataflow-to-file",
    "credential-dataflow-to-network",
    "credential-dataflow-to-process",
    "credential-source-near-file",
    "credential-source-near-network",
    "credential-source-near-process",
    "credential-global-state-key",
    "credential-global-state-storage",
    "credential-inputbox-prompt",
    "clipboard-read-near-secret-input",
    "clipboard-near-credential-surface",
    "credential-input-near-state",
    "unrestricted-workspace-cli-path",
}
MALWARE_REMOVAL_TYPES = {"malware"}
SUSPICIOUS_REMOVAL_TYPES = {"suspicious"}
SENSITIVE_TEXT_RE = re.compile(
    r"("
    r"api[-_ ]?(key|token)|api(key|token)|access[-_ ]?token|accessToken|"
    r"refresh[-_ ]?token|refreshToken|auth[-_ ]?token|authToken|bearer|"
    r"password|passwd|pwd|secret|credential|private[-_ ]?key|privateKey|"
    r"client[-_ ]?secret|clientSecret|github[-_ ]?token|githubToken|npm[-_ ]?token|npmToken|"
    r"(?:openai|anthropic|claude|gemini|azure|cohere|mistral|huggingface|hf)[-_ ]?(?:api[-_ ]?)?(?:key|token|secret|credential)|"
    r"aws[-_ ]?(secret|key)|aws(secret|key)|webhook|session[-_ ]?token|sessionToken|cookie"
    r")",
    re.I,
)
SENSITIVE_TEXT_NEGATIVE_RE = re.compile(
    r"\b(keyboard|keybinding|shortcut|translation[-_ ]?key|object[-_ ]?key|primary[-_ ]?key|"
    r"foreign[-_ ]?key|sort[-_ ]?key|map[-_ ]?key)\b",
    re.I,
)


def scan_targets(
    paths: list[Path | str] | None = None,
    extension_ids: list[str] | None = None,
    marketplace_scan_ids: list[str] | None = None,
    marketplace_version: str | None = None,
    include_fixtures: bool = False,
    all_local: bool = False,
    online: bool = False,
    known_bad_hashes_file: Path | str | None = None,
    threat_feed_file: Path | str | None = None,
    extension_advisories_file: Path | str | None = None,
    registry_snapshot_file: Path | str | None = None,
    sandbox_observations_file: Path | str | None = None,
    previous_report_file: Path | str | None = None,
    include_posture: bool = True,
) -> dict[str, Any]:
    targets: list[dict[str, str]] = []
    root = Path.cwd()

    if include_fixtures:
        targets.extend(discover_from_path(root / "fixtures"))
    for path in paths or []:
        targets.extend(discover_from_path(path))
    if all_local:
        targets.extend(discover_local_installations())

    unique: dict[str, dict[str, str]] = {}
    for target in targets:
        unique[target["path"]] = target

    known_bad_hashes = _load_known_bad_hashes(known_bad_hashes_file)
    extensions = [
        _scan_discovered_target(target, known_bad_hashes)
        for target in unique.values()
    ]
    extensions.extend(_registry_only_extension(extension_id) for extension_id in extension_ids or [])
    extensions.extend(
        scan_marketplace_extension(identifier, version=marketplace_version, known_bad_hashes=known_bad_hashes)
        for identifier in marketplace_scan_ids or []
    )
    _apply_threat_feed(extensions, _load_threat_feed(threat_feed_file))
    advisory_bundle = _load_extension_advisories(extension_advisories_file)
    _apply_extension_advisories(extensions, advisory_bundle)
    _apply_sandbox_observations(extensions, _load_sandbox_observations(sandbox_observations_file))
    registry = (
        _load_registry_snapshot(registry_snapshot_file)
        if registry_snapshot_file is not None
        else _capture_registry_snapshot(enrich_registry(extensions, online=online), source="live")
    )
    _apply_registry_findings(extensions, registry["findings"])
    dependency_errors = [
        item for item in registry.get("errors", [])
        if isinstance(item, dict) and str(item.get("source") or "").startswith("osv")
    ]
    registry_enabled = bool(registry.get("enabled"))
    registry_identity = registry.get("snapshot") if isinstance(registry.get("snapshot"), dict) else {}
    for extension in extensions:
        acquisition_failure = str(extension.artifact_inventory.get("skipped_reason") or "") if extension.source == "marketplace-error" else ""
        providers = extension.analysis_coverage.setdefault("providers", {})
        if acquisition_failure:
            providers["artifact_acquisition"] = {
                "provider": "artifact_acquisition",
                "status": "failed",
                "error": acquisition_failure,
                "error_count": 1,
                "required": True,
            }
        providers["dependency_intelligence"] = {
            "provider": "dependency_intelligence",
            "status": "completed" if registry_enabled and not dependency_errors else "failed" if registry_enabled else "unavailable",
            "snapshot_sha256": str(registry_identity.get("sha256") or ""),
            "error_count": len(dependency_errors),
            "required": False,
        }
        providers["extension_advisories"] = {
            "provider": "extension_advisories",
            "status": str(advisory_bundle.get("status") or "unavailable"),
            "snapshot_version": str(advisory_bundle.get("snapshot_version") or "unavailable"),
            "sha256": str(advisory_bundle.get("sha256") or ""),
            "error_count": 0 if advisory_bundle.get("status") == "completed" else 1,
            "required": True,
        }
        _finalize_analysis_coverage(extension.analysis_coverage)
        extension.artifact_inventory["analysis_coverage"] = extension.analysis_coverage
        extension.artifact_inventory["scan_incomplete"] = extension.analysis_coverage["status"] != "complete"
        coverage_limitations = "; ".join(extension.analysis_coverage["limitations"])
        extension.artifact_inventory["skipped_reason"] = "; ".join(item for item in (acquisition_failure, coverage_limitations) if item)
        # Registry identity and dependency-provider coverage are attached after
        # the artifact scan. Recompute the decision and public explanation only
        # after that final evidence is present so CLI, worker, and website
        # ingestion all serialize the same canonical assessment.
        _apply_security_decision(extension)
        apply_public_assessment(extension)
    intelligence = {
        "extension_advisories": {
            "status": str(advisory_bundle.get("status") or "unavailable"),
            "snapshot_version": str(advisory_bundle.get("snapshot_version") or "none"),
            "sha256": str(advisory_bundle.get("sha256") or ""),
        },
        "registry": {
            "status": "completed" if registry_enabled and not registry.get("errors") else "failed" if registry_enabled else "unavailable",
            "source": str(registry_identity.get("source") or "unavailable"),
            "sha256": str(registry_identity.get("sha256") or ""),
        },
    }
    return _build_report(
        extensions,
        registry,
        _load_previous_report(previous_report_file),
        include_posture=include_posture,
        intelligence=intelligence,
    )


def _registry_snapshot_payload(registry: dict[str, Any]) -> dict[str, Any]:
    return {
        "enabled": bool(registry.get("enabled")),
        "mode": str(registry.get("mode") or "disabled"),
        "findings": list(registry.get("findings") or []),
        "errors": list(registry.get("errors") or []),
    }


def _capture_registry_snapshot(registry: dict[str, Any], *, source: str) -> dict[str, Any]:
    payload = _registry_snapshot_payload(registry)
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return {
        **payload,
        "snapshot": {
            "schema_version": "1",
            "source": source,
            "sha256": digest,
        },
    }


def _load_registry_snapshot(path: Path | str) -> dict[str, Any]:
    snapshot_path = Path(path)
    try:
        parsed = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Registry intelligence snapshot could not be read: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("Registry intelligence snapshot must be a JSON object.")
    candidate = parsed.get("registry_checks") if isinstance(parsed.get("registry_checks"), dict) else parsed
    if not isinstance(candidate.get("findings"), list) or not isinstance(candidate.get("errors"), list):
        raise ValueError("Registry intelligence snapshot must include findings and errors arrays.")
    captured = _capture_registry_snapshot(candidate, source="replay")
    claimed = candidate.get("snapshot") if isinstance(candidate.get("snapshot"), dict) else {}
    claimed_digest = str(claimed.get("sha256") or "")
    if claimed_digest and claimed_digest != captured["snapshot"]["sha256"]:
        raise ValueError("Registry intelligence snapshot digest does not match its contents.")
    return captured


def scan_extension(path: Path, source: str = "vscode", known_bad_hashes: dict[str, dict[str, Any]] | None = None) -> ExtensionReport:
    manifest, manifest_status = _read_manifest_status(path / "package.json")
    name = str(manifest.get("name") or path.name)
    publisher = str(manifest.get("publisher") or "unknown")
    version = str(manifest.get("version") or "0.0.0")
    extension_id = f"{publisher}.{name}"
    findings: list[Finding] = []
    capabilities: dict[str, dict[str, Any]] = {}
    scanned_files = 0
    executable_sources: list[tuple[str, str]] = []
    source_previews: list[dict[str, Any]] = []
    js_ast_statuses: list[str] = []
    js_ast_failed_paths: list[str] = []
    ast_unparsed_entrypoints: list[str] = []

    _add_manifest_findings(extension_id, version, manifest, findings, capabilities)
    _add_dependency_source_findings(extension_id, version, manifest, findings)

    files = _walk_extension_files(path)
    entrypoints = _declared_entrypoints(manifest, path)
    artifact_inventory = _artifact_inventory(path, files)
    analysis_coverage = _new_analysis_coverage(files, entrypoints, path)
    _add_artifact_inventory_findings(extension_id, version, artifact_inventory, known_bad_hashes or {}, findings, capabilities, path)
    _add_repository_posture_findings(extension_id, version, manifest, path, findings, artifact_inventory)

    # Analyze declared activation paths first. Besides making the security-
    # critical path explicit, this prevents hundreds of auxiliary-file
    # findings from consuming the memory headroom needed by AST analysis of a
    # large bundled entrypoint. Inventory order remains untouched.
    analysis_files = sorted(
        files,
        key=lambda candidate: (
            candidate.relative_to(path).as_posix() not in entrypoints,
            candidate.relative_to(path).as_posix(),
        ),
    )
    for file in analysis_files:
        rel = file.relative_to(path).as_posix()
        suffix = file.suffix.lower()
        is_entrypoint = rel in entrypoints
        if file.is_symlink():
            if suffix in EXEC_TEXT_EXTS and (is_entrypoint or not _is_ignored_static_asset(rel)):
                analysis_coverage["read_failures"].append(rel)
            continue
        if suffix in BINARY_RISK_EXTS:
            continue
        if suffix not in TEXT_EXTS or (_is_ignored_static_asset(rel) and not is_entrypoint):
            continue

        text = _read_text(file)
        if text is None:
            if suffix in EXEC_TEXT_EXTS:
                analysis_coverage["read_failures"].append(rel)
            continue
        if file.stat().st_size > MAX_TEXT_BYTES:
            analysis_coverage["oversized_files"].append(rel)
            continue
        if len(source_previews) < MAX_SOURCE_PREVIEWS and len(text.encode("utf-8")) <= MAX_SOURCE_PREVIEW_BYTES:
            source_previews.append({
                "path": rel,
                "content": text,
                "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "truncated": False,
            })
        scanned_files += 1
        # Run the bounded AST subprocess before expanding raw-text matches into
        # Python Finding objects. Large bundled entrypoints can otherwise push
        # the parent close to the container memory limit and starve Node's GC,
        # turning identical source into a resource-dependent timeout.
        if suffix in JS_AST_EXTS:
            generated_blob = _is_generated_code_blob(rel, text)
            if is_entrypoint or not generated_blob:
                status = _add_ast_findings(extension_id, version, rel, text, findings, generated=generated_blob)
                js_ast_statuses.append(status)
                if status not in ("ok", "unparsed"):
                    js_ast_failed_paths.append(rel)
                if is_entrypoint and status == "unparsed":
                    ast_unparsed_entrypoints.append(rel)
        if suffix in EXEC_TEXT_EXTS:
            analysis_coverage["analyzed_executable_files"].append(rel)
            executable_sources.append((rel, text))
            _add_code_findings(extension_id, version, rel, text, findings, capabilities)
        if suffix in EXEC_TEXT_EXTS or suffix in {".html", ".htm"}:
            _add_webview_csp_findings(
                extension_id,
                version,
                rel,
                text,
                findings,
                report_missing=not (suffix in JS_AST_EXTS and _is_generated_code_blob(rel, text)),
            )

    _add_workspace_cli_path_findings(extension_id, version, manifest, executable_sources, findings)

    if ast_unparsed_entrypoints:
        # A declared activation entrypoint whose source the AST layer cannot
        # parse (TypeScript/JSX shipped un-transpiled, or genuinely malformed
        # JS) loses structural evasion detection for that file. The raw-text
        # rule layer still covers it, so the provider stays "completed" -- but
        # a silent pass here would let the primary code path skate on
        # regex-only coverage. Surface it as a posture-class review nudge so
        # the extension cannot reach "allow" without a human confirming the
        # entrypoint is benign.
        listed = ", ".join(sorted(ast_unparsed_entrypoints)[:5])
        findings.append(_finding(
            extension_id,
            version,
            "entrypoint-ast-unparsed",
            "code",
            "LOW",
            _SEVERITY_TO_CONFIDENCE["LOW"],
            f"Declared entrypoint(s) could not be parsed by the AST layer (plain-JS only): {listed}. "
            "Structural obfuscation detection did not run on this file; only raw-text rules applied.",
            sorted(ast_unparsed_entrypoints)[:5],
            "Confirm the entrypoint is benign; AST-level evasion checks did not cover it because acorn parses plain JavaScript only.",
            evidence={"unparsed_entrypoints": sorted(ast_unparsed_entrypoints)},
        ))


    provider_findings, provider_statuses = run_static_providers(path, extension_id, version)
    findings.extend(provider_findings)
    findings = _dedupe_findings(findings)
    analysis_coverage["providers"] = {
        "native_static": {"provider": "native_static", "status": "completed", "required": True},
        "javascript_ast": _javascript_ast_provider_status(js_ast_statuses, js_ast_failed_paths),
        **provider_statuses,
    }
    analysis_coverage["manifest_validation"] = {
        "status": manifest_status,
        "valid": manifest_status == "valid",
    }
    if manifest_status != "valid":
        analysis_coverage.setdefault("read_failures", [])
        analysis_coverage["manifest_error"] = manifest_status
    verdict, verdict_reason, malware_authority, severity, malware_score, risk_score, score_details = _classify_findings(findings)

    _finalize_analysis_coverage(analysis_coverage)
    artifact_inventory["analysis_coverage"] = analysis_coverage
    artifact_inventory["scan_incomplete"] = analysis_coverage["status"] != "complete"
    artifact_inventory["skipped_reason"] = "; ".join(analysis_coverage["limitations"])
    artifact_hash = str(artifact_inventory.get("package_hash") or "")
    dependencies = _dependencies(manifest, path)
    artifact_inventory["dependency_inventory"] = _dependency_inventory(manifest, dependencies)
    artifact_inventory["source_previews"] = source_previews
    report = ExtensionReport(
        instance_id=_stable_id(str(path)),
        extension_id=extension_id,
        name=name,
        publisher=publisher,
        version=version,
        description=str(manifest.get("description") or ""),
        repository=_repository_url(manifest.get("repository")),
        install_path=str(path),
        source=source,
        artifact_hash=artifact_hash,
        severity=severity,
        verdict=verdict,
        malware_authority=malware_authority,
        verdict_reason=verdict_reason,
        malware_score=malware_score,
        risk_score=risk_score,
        score_details=score_details,
        capabilities=list(capabilities.values()),
        artifact_inventory=artifact_inventory,
        findings=findings,
        scanned_files=scanned_files,
        dependencies=dependencies,
        artifact_identity={
            "extension_id": extension_id,
            "version": version,
            "sha256": artifact_hash,
            "source": source,
            "signature": dict(artifact_inventory.get("vsix_signature") or {}),
        },
        analysis_coverage=analysis_coverage,
    )
    _apply_security_decision(report)
    apply_public_assessment(report)
    return report


def scan_vsix(path: Path, known_bad_hashes: dict[str, dict[str, Any]] | None = None) -> ExtensionReport:
    original_path = path.expanduser().resolve()
    with tempfile.TemporaryDirectory(prefix="ide-scanner-vsix-src-") as src_tmp:
        # Some upload/download sources (browser fetches, the marketplace
        # vspackage endpoint) hand back a gzip-wrapped VSIX instead of a raw
        # zip. Unwrap a *copy* in scratch space so the caller's original
        # file is never mutated in place, and never mixed into the
        # extraction directory the scanner later walks.
        vsix_path = Path(src_tmp) / f"source{original_path.suffix or '.vsix'}"
        shutil.copyfile(original_path, vsix_path)
        _degzip_if_needed(vsix_path)
        vsix_hash, vsix_size = _hash_file(vsix_path)
        with tempfile.TemporaryDirectory(prefix="ide-scanner-vsix-") as tmp:
            tmp_root = Path(tmp)
            archive_anomalies = _safe_extract_vsix(vsix_path, tmp_root)
            extension_root = _find_extracted_extension_root(tmp_root)
            report = scan_extension(extension_root, source="vsix", known_bad_hashes=known_bad_hashes)
            report.install_path = str(original_path)
            report.source = "vsix"
            report.artifact_hash = vsix_hash
            report.artifact_inventory["vsix_hash"] = vsix_hash
            report.artifact_inventory["vsix_size_bytes"] = vsix_size
            report.artifact_inventory["source_artifact"] = original_path.name
            report.artifact_inventory["vsix_signature"] = _vsix_signature_status(tmp_root)
            _record_archive_anomalies(report, archive_anomalies)
            report.artifact_identity = {
                "extension_id": report.extension_id,
                "version": report.version,
                "sha256": vsix_hash,
                "source": "vsix",
                "signature": dict(report.artifact_inventory["vsix_signature"]),
            }
        _apply_vsix_known_bad_match(report, known_bad_hashes or {})
        _apply_security_decision(report)
        apply_public_assessment(report)
        return report


def _scan_discovered_target(target: dict[str, str], known_bad_hashes: dict[str, dict[str, Any]]) -> ExtensionReport:
    """Scan one discovered local target, isolating failures.

    A single malformed or hostile artifact (bad zip, extraction-limit abort,
    unreadable tree) must never abort an entire inventory scan. On failure we
    emit an ``incomplete`` placeholder for that artifact and let the rest of the
    inventory complete."""
    path = Path(target["path"])
    try:
        if target.get("type") == "vsix":
            return scan_vsix(path, known_bad_hashes=known_bad_hashes)
        return scan_extension(path, source=target.get("type", "vscode"), known_bad_hashes=known_bad_hashes)
    except Exception as exc:  # noqa: BLE001 - isolate any per-artifact failure
        return _local_error_extension(path, target.get("type", "vscode"), f"{type(exc).__name__}: {exc}")


def _local_error_extension(path: Path, source: str, message: str) -> ExtensionReport:
    reason = f"Scan aborted for this artifact and was isolated: {message}"
    artifact_inventory = _empty_artifact_inventory()
    artifact_inventory["scan_incomplete"] = True
    artifact_inventory["skipped_reason"] = reason
    artifact_inventory["analysis_coverage"] = {
        "status": "incomplete",
        "coverage_percent": 0,
        "limitations": [reason],
        "manifest_validation": {"valid": False, "status": "scan-aborted"},
        "providers": {},
    }
    name = path.name or "unknown"
    return ExtensionReport(
        instance_id=_stable_id(str(path)),
        extension_id=f"unknown.{name}",
        name=name,
        publisher="unknown",
        version="unknown",
        description="",
        repository="",
        install_path=str(path),
        source=source,
        artifact_hash="",
        severity="INFO",
        verdict="clean",
        malware_authority="none",
        verdict_reason=reason,
        malware_score=0,
        risk_score=0,
        score_details=_empty_score_details(),
        capabilities=[],
        artifact_inventory=artifact_inventory,
        findings=[],
        scanned_files=0,
        dependencies={},
        analysis_coverage=artifact_inventory["analysis_coverage"],
    )


def scan_marketplace_extension(
    identifier: str,
    version: str | None = None,
    known_bad_hashes: dict[str, dict[str, Any]] | None = None,
) -> ExtensionReport:
    """Download a VSIX from the VS Marketplace gallery and run the normal
    quarantine-extraction static scan on it (scan_vsix). This is a hosted,
    static-only path: it must never invoke sandbox_runner.run_sandbox(...,
    allow_execute=True) against attacker-controlled marketplace content."""
    try:
        resolved_id = parse_marketplace_reference(identifier)
    except MarketplaceDownloadError as exc:
        return _marketplace_error_extension(identifier, str(exc))

    registry_source: dict[str, str] = {}
    try:
        vsix_path = download_marketplace_vsix(resolved_id, version=version, registry_out=registry_source)
    except MarketplaceDownloadError as exc:
        return _marketplace_error_extension(resolved_id, str(exc))

    try:
        report = scan_vsix(vsix_path, known_bad_hashes=known_bad_hashes)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return _marketplace_error_extension(resolved_id, f"Downloaded VSIX could not be scanned: {exc}")
    finally:
        vsix_path.unlink(missing_ok=True)

    if report.extension_id.lower() != resolved_id.lower() or (version and report.version != version):
        actual = f"{report.extension_id}@{report.version}"
        expected = f"{resolved_id}@{version or report.version}"
        return _marketplace_error_extension(
            resolved_id,
            f"Registry returned {actual} while {expected} was requested; result rejected.",
        )

    report.source = registry_source.get("registry", "marketplace")
    report.install_path = f"{report.source}:{resolved_id}"
    return report


def _marketplace_error_extension(identifier: str, message: str) -> ExtensionReport:
    publisher, _, name = identifier.partition(".")
    if not name:
        publisher = "unknown"
        name = identifier
    artifact_inventory = _empty_artifact_inventory()
    artifact_inventory["scan_incomplete"] = True
    artifact_inventory["skipped_reason"] = message
    return ExtensionReport(
        instance_id=_stable_id(f"marketplace:{identifier}"),
        extension_id=identifier,
        name=name,
        publisher=publisher,
        version="unknown",
        description="",
        repository="",
        install_path=f"marketplace:{identifier}",
        source="marketplace-error",
        artifact_hash="",
        severity="INFO",
        verdict="clean",
        malware_authority="none",
        verdict_reason=message,
        malware_score=0,
        risk_score=0,
        score_details=_empty_score_details(),
        capabilities=[],
        artifact_inventory=artifact_inventory,
        findings=[],
        scanned_files=0,
        dependencies={},
    )


def _registry_only_extension(extension_id: str) -> ExtensionReport:
    publisher, _, name = extension_id.partition(".")
    if not name:
        publisher = "unknown"
        name = extension_id
    artifact_inventory = _empty_artifact_inventory()
    artifact_inventory["scan_incomplete"] = True
    artifact_inventory["skipped_reason"] = "No local extension artifact was provided; executable analysis was not performed."
    return ExtensionReport(
        instance_id=_stable_id(f"registry:{extension_id}"),
        extension_id=extension_id,
        name=name,
        publisher=publisher,
        version="unknown",
        description="",
        repository="",
        install_path="",
        source="registry-id",
        artifact_hash="",
        severity="INFO",
        verdict="clean",
        malware_authority="none",
        verdict_reason="No local extension package was provided; only registry checks can run.",
        malware_score=0,
        risk_score=0,
        score_details=_empty_score_details(),
        capabilities=[],
        artifact_inventory=artifact_inventory,
        findings=[],
        scanned_files=0,
        dependencies={},
    )


def _add_manifest_findings(
    extension_id: str,
    version: str,
    manifest: dict[str, Any],
    findings: list[Finding],
    capabilities: dict[str, dict[str, Any]],
) -> None:
    activation = [str(item) for item in manifest.get("activationEvents") or []]
    sensitive_prefixes = ("onUri", "onAuthenticationRequest", "onTerminal", "onTaskType", "onDebug", "onWebviewPanel", "onCustomEditor")
    for event in activation:
        if event == "*":
            findings.append(_finding(
                extension_id,
                version,
                "broad-activation",
                "activation",
                "LOW",
                0.52,
                "Extension activates for every workspace.",
                ["package.json"],
                "Prefer event-scoped activation unless the extension genuinely needs global startup behavior.",
            ))
        elif event == "onStartupFinished":
            findings.append(_finding(
                extension_id,
                version,
                "startup-activation",
                "activation",
                "LOW",
                0.45,
                "Extension runs automatically after IDE startup.",
                ["package.json"],
                "Review whether startup activation is necessary for this extension.",
            ))
        elif event.startswith(sensitive_prefixes):
            findings.append(_finding(
                extension_id,
                version,
                "sensitive-activation",
                "activation",
                "LOW",
                0.5,
                f"Extension activates on sensitive IDE event: {event}.",
                ["package.json"],
                "Check whether this activation path matches the extension's purpose.",
                {"activation_event": event},
            ))
        if event.startswith("onCommand:") and re.search(
            r"(?:^|[._-])(?:login|log-in|signin|sign-in|authenticate|authentication|credential|token|secret|password)(?:$|[._-])",
            event.removeprefix("onCommand:"),
            re.I,
        ):
            findings.append(_finding(
                extension_id,
                version,
                "credential-command-registration",
                "cross-extension-exposure",
                "LOW",
                0.68,
                f"Manifest activates on a credential-related command: {event.removeprefix('onCommand:')}.",
                ["package.json"],
                "Review whether other extensions can invoke this command and whether credential access requires explicit user intent.",
                {"command": event.removeprefix("onCommand:"), "surface": "ActivationEvent"},
            ))
    if activation:
        capabilities["activation"] = {"id": "activation", "evidence": activation}

    scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    for script_name in ("preinstall", "install", "postinstall", "vscode:uninstall"):
        if script_name in scripts:
            findings.append(_finding(
                extension_id,
                version,
                "lifecycle-script",
                "supply-chain",
                "MEDIUM",
                0.7,
                f"Package defines a lifecycle script: {script_name}.",
                ["package.json"],
                "Inspect lifecycle scripts because they execute outside normal extension UI flows.",
                {"script": script_name, "command": scripts[script_name]},
            ))
            capabilities.setdefault("lifecycle_scripts", {"id": "lifecycle_scripts", "evidence": []})["evidence"].append(script_name)
            _add_lifecycle_script_chain_findings(extension_id, version, script_name, str(scripts[script_name]), findings)

    contributes = manifest.get("contributes") if isinstance(manifest.get("contributes"), dict) else {}
    for key in ("debuggers", "taskDefinitions", "terminal"):
        if key in contributes:
            findings.append(_finding(
                extension_id,
                version,
                "powerful-ide-contribution",
                "ide-capability",
                "LOW",
                0.5,
                f"Extension contributes IDE capability: {key}.",
                ["package.json"],
                "Validate that this capability is core to the extension's stated function.",
                {"contribution": key},
            ))
            capabilities.setdefault("ide_contributions", {"id": "ide_contributions", "evidence": []})["evidence"].append(key)
    for key in ("languageModelTools", "chatParticipants", "mcpServers"):
        if key in contributes:
            findings.append(_finding(
                extension_id,
                version,
                "agentic-tooling",
                "agentic",
                "MEDIUM",
                0.66,
                f"Extension contributes agent-facing capability: {key}.",
                ["package.json"],
                "Review tool permissions and approval behavior before trusting agent-facing extensions.",
                {"contribution": key},
            ))
            capabilities.setdefault("agentic", {"id": "agentic", "evidence": []})["evidence"].append(key)
            _add_agent_capability_findings(extension_id, version, key, contributes.get(key), findings, capabilities)
    _add_cross_extension_manifest_findings(extension_id, version, contributes, findings, capabilities)


def _add_dependency_source_findings(
    extension_id: str,
    version: str,
    manifest: dict[str, Any],
    findings: list[Finding],
) -> None:
    for name, spec in _manifest_runtime_dependencies(manifest).items():
        normalized = spec.strip().lower()
        if normalized in {"*", "latest", "x"} or normalized.endswith(".x"):
            findings.append(_finding(
                extension_id,
                version,
                "unpinned-dependency",
                "dependency",
                "LOW",
                0.62,
                f"Runtime dependency {name} uses an unpinned version specifier: {spec}.",
                ["package.json"],
                "Pin runtime dependencies or resolve them through a lockfile before trusting the artifact.",
                {"package": name, "specifier": spec},
            ))
        elif _is_mutable_dependency_spec(normalized):
            findings.append(_finding(
                extension_id,
                version,
                "mutable-dependency-source",
                "dependency",
                "MEDIUM",
                0.68,
                f"Runtime dependency {name} is loaded from a mutable or non-registry source: {spec}.",
                ["package.json"],
                "Verify the source is expected, immutable, and pinned to a commit or checksum.",
                {"package": name, "specifier": spec},
            ))


_CONFIGURED_EXECFILE_RE = re.compile(
    r"(?:const|let|var)\s+(?P<var>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:[A-Za-z_$][\w$]*\.)?workspace\.getConfiguration\(\s*['\"](?P<section>[^'\"]+)['\"]\s*\)"
    r"\s*\.get\(\s*['\"](?P<key>[^'\"]+)['\"]"
    r"[\s\S]{0,1500}?\bexecFile(?:Sync)?\s*\(\s*(?P=var)\b"
)


def _add_workspace_cli_path_findings(
    extension_id: str,
    version: str,
    manifest: dict[str, Any],
    sources: list[tuple[str, str]],
    findings: list[Finding],
) -> None:
    """Detect workspace-configured executable paths lacking trust restrictions.

    VS Code lets an extension declare configuration keys that are unavailable in
    untrusted workspaces. If a workspace-controlled setting selects the binary
    passed to execFile and is not restricted, opening a repository can redirect
    execution to a workspace-provided program. This is a concrete manifest/code
    boundary defect, not generic process capability.
    """
    capabilities = manifest.get("capabilities") if isinstance(manifest.get("capabilities"), dict) else {}
    trust = capabilities.get("untrustedWorkspaces") if isinstance(capabilities.get("untrustedWorkspaces"), dict) else {}
    if trust.get("supported") is False:
        return
    restricted = {
        str(item)
        for item in trust.get("restrictedConfigurations") or []
        if isinstance(item, str)
    }
    contributes = manifest.get("contributes") if isinstance(manifest.get("contributes"), dict) else {}
    declared_configurations = {
        str(item.get("key"))
        for item in _manifest_configuration_items(contributes)
        if item.get("key")
    }
    for rel, text in sources:
        for match in _CONFIGURED_EXECFILE_RE.finditer(text):
            config_key = f"{match.group('section')}.{match.group('key')}"
            if config_key not in declared_configurations:
                continue
            if config_key in restricted:
                continue
            findings.append(_finding(
                extension_id,
                version,
                "unrestricted-workspace-cli-path",
                "execution",
                "HIGH",
                0.84,
                f"Workspace configuration {config_key} selects the executable passed to execFile without an untrusted-workspace restriction.",
                [rel, "package.json"],
                "Add the configuration key to capabilities.untrustedWorkspaces.restrictedConfigurations or disable the extension in untrusted workspaces.",
                {
                    "evidence_class": "exposure",
                    "configuration_key": config_key,
                    "sink": "execFile",
                },
            ))
def _add_lifecycle_script_chain_findings(
    extension_id: str,
    version: str,
    script_name: str,
    command: str,
    findings: list[Finding],
) -> None:
    text = command.lower()
    evidence = {"script": script_name, "command": command}
    has_download = bool(re.search(
        r"\b(?:curl|wget|invoke-webrequest|irm)\b|\bfetch\s*(?:\(|\s+)\s*['\"]?https?://",
        text,
    ))
    has_execute = bool(re.search(r"\b(node|npm|npx|bash|sh|zsh|powershell|pwsh|python|chmod|exec)\b", text))
    if has_download and has_execute:
        findings.append(_finding(
            extension_id,
            version,
            "install-download-execute",
            "install-time",
            "HIGH",
            0.82,
            f"Lifecycle script {script_name} can download content and execute commands.",
            ["package.json"],
            "Require pinned URLs, checksums, signatures, and a clear install-time purpose.",
            evidence,
        ))
    if re.search(r"(\.npmrc|\.ssh|\.env|aws_access_key_id|aws_secret_access_key|npm_token|github_token|google_application_credentials)", text):
        findings.append(_finding(
            extension_id,
            version,
            "install-secret-access",
            "install-time",
            "HIGH",
            0.84,
            f"Lifecycle script {script_name} references credential material.",
            ["package.json"],
            "Do not allow install-time scripts to access local credentials without explicit justification.",
            evidence,
        ))
    if re.search(r"(base64\s+-d|frombase64string|eval|iex|invoke-expression|curl[^|]+\|\s*(bash|sh)|wget[^|]+\|\s*(bash|sh))", text):
        findings.append(_finding(
            extension_id,
            version,
            "install-shell-obfuscation",
            "install-time",
            "HIGH",
            0.82,
            f"Lifecycle script {script_name} contains obfuscated or piped shell execution.",
            ["package.json"],
            "Block or manually review obfuscated install-time shell behavior.",
            evidence,
        ))
    if has_download and re.search(r"(telemetry|analytics|posthog|segment|mixpanel|amplitude|track|metrics)", text):
        findings.append(_finding(
            extension_id,
            version,
            "install-network-telemetry",
            "install-time",
            "MEDIUM",
            0.62,
            f"Lifecycle script {script_name} appears to send install-time telemetry.",
            ["package.json"],
            "Confirm telemetry is declared, minimal, and opt-out capable.",
            evidence,
        ))


def _add_agent_capability_findings(
    extension_id: str,
    version: str,
    key: str,
    value: Any,
    findings: list[Finding],
    capabilities: dict[str, dict[str, Any]],
) -> None:
    text = json.dumps(value, sort_keys=True).lower() if value is not None else ""
    if not text:
        return
    checks = [
        ("agent-shell-tool", r"\b(shell|terminal|command|exec|spawn|process|subprocess|bash|powershell|cmd)\b", "Agent-facing tool surface can run shell or process commands.", "agent_shell"),
        ("agent-filesystem-tool", r"\b(file|filesystem|workspace|readfile|writefile|path|directory|folder|glob)\b", "Agent-facing tool surface can read or write files.", "agent_filesystem"),
        ("agent-network-tool", r"\b(http|https|url|fetch|request|websocket|network|api)\b", "Agent-facing tool surface can reach network resources.", "agent_network"),
    ]
    for rule_id, pattern, summary, capability_id in checks:
        if re.search(pattern, text):
            findings.append(_finding(
                extension_id,
                version,
                rule_id,
                "agentic",
                "MEDIUM",
                0.68,
                summary,
                ["package.json"],
                "Review agent tool schemas, approval requirements, and data boundaries.",
                {"contribution": key},
            ))
            capabilities.setdefault(capability_id, {"id": capability_id, "evidence": []})["evidence"].append(key)
    if key == "mcpServers":
        findings.append(_finding(
            extension_id,
            version,
            "mcp-server-command",
            "agentic",
            "MEDIUM",
            0.66,
            "Extension registers an MCP server command or server definition.",
            ["package.json"],
            "Verify the MCP server command, package source, pinning, and tool permissions.",
            {"contribution": key},
        ))
    if re.search(r"\b(prompt|instruction|webview|markdown|html|remotecontent|usercontent)\b", text) and re.search(r"\b(tool|command|execute|shell|terminal)\b", text):
        findings.append(_finding(
            extension_id,
            version,
            "agent-prompt-injection-sink",
            "agentic",
            "MEDIUM",
            0.58,
            "Agent-facing contribution may route untrusted content into tool execution context.",
            ["package.json"],
            "Review prompt/tool boundaries and sanitize untrusted content before tool invocation.",
            {"contribution": key},
        ))


def _add_cross_extension_manifest_findings(
    extension_id: str,
    version: str,
    contributes: dict[str, Any],
    findings: list[Finding],
    capabilities: dict[str, dict[str, Any]],
) -> None:
    for item in _manifest_configuration_items(contributes):
        text = " ".join(str(item.get(field) or "") for field in ("key", "title", "description", "markdownDescription"))
        if not _looks_sensitive_text(text):
            continue
        key = str(item.get("key") or "")
        findings.append(_finding(
            extension_id,
            version,
            "credential-config-key",
            "cross-extension-exposure",
            "LOW",
            _sensitive_text_confidence(text, base=0.62),
            f"Manifest declares a credential-related configuration surface: {key}.",
            ["package.json"],
            "Prefer VS Code SecretStorage for credentials and document whether other extensions can read or influence this configuration.",
            {"configuration_key": key, "text": _truncate_evidence_text(text), "surface": "RequestedConfiguration"},
        ))
        capabilities.setdefault("credential_configuration", {"id": "credential_configuration", "evidence": []})["evidence"].append(key)

    for command in _manifest_commands(contributes):
        text = " ".join(str(command.get(field) or "") for field in ("command", "title", "category"))
        if not _looks_sensitive_text(text):
            continue
        command_id = str(command.get("command") or "")
        findings.append(_finding(
            extension_id,
            version,
            "credential-command-registration",
            "cross-extension-exposure",
            "LOW",
            _sensitive_text_confidence(text, base=0.58),
            f"Manifest declares a credential-related command surface: {command_id}.",
            ["package.json"],
            "Review whether this command can be invoked by other extensions and whether it gates credential access with user intent.",
            {"command": command_id, "text": _truncate_evidence_text(text), "surface": "RequestedCommands"},
        ))
        capabilities.setdefault("credential_commands", {"id": "credential_commands", "evidence": []})["evidence"].append(command_id)


def _add_repository_posture_findings(
    extension_id: str,
    version: str,
    manifest: dict[str, Any],
    path: Path,
    findings: list[Finding],
    artifact_inventory: dict[str, Any] | None = None,
) -> None:
    if not _repository_url(manifest.get("repository")):
        findings.append(_finding(
            extension_id,
            version,
            "repo-url-missing",
            "reputation",
            "LOW",
            0.5,
            "Extension manifest does not declare a source repository.",
            ["package.json"],
            "A source repository improves provenance review but absence is not malware evidence.",
        ))
    if not any((path / item).exists() for item in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")):
        findings.append(_finding(
            extension_id,
            version,
            "security-policy-missing",
            "repository-posture",
            "LOW",
            0.42,
            "No local security policy file was found in the packaged artifact.",
            [],
            "Treat as posture context only; small extensions may not ship security policy files.",
        ))
    if not any((path / item).exists() for item in ("LICENSE", "LICENSE.md", "LICENSE.txt", "license", "license.md")):
        findings.append(_finding(
            extension_id,
            version,
            "license-missing",
            "repository-posture",
            "LOW",
            0.4,
            "No local LICENSE file was found in the packaged artifact.",
            [],
            "Treat as posture context only; absence of a license file is not malware evidence.",
        ))
    for artifact in (artifact_inventory or {}).get("risky_artifacts", []):
        if artifact.get("kind") != "native":
            continue
        rel = str(artifact["path"])
        findings.append(_finding(
            extension_id,
            version,
            "repo-binary-artifacts",
            "repository-posture",
            "LOW",
            0.5,
            f"Packaged artifact ships a committed native binary: {rel}.",
            [rel],
            "Confirm committed binaries are expected and, where possible, built reproducibly rather than checked in directly.",
        ))
    for workflow in (path / ".github" / "workflows").glob("*.yml"):
        text = _read_text(workflow) or ""
        _add_workflow_findings(extension_id, version, workflow.relative_to(path).as_posix(), text, findings)
    for workflow in (path / ".github" / "workflows").glob("*.yaml"):
        text = _read_text(workflow) or ""
        _add_workflow_findings(extension_id, version, workflow.relative_to(path).as_posix(), text, findings)


def _add_workflow_findings(extension_id: str, version: str, rel: str, text: str, findings: list[Finding]) -> None:
    lowered = text.lower()
    if "pull_request_target" in lowered or "permissions: write-all" in lowered or re.search(r"contents:\s*write", lowered):
        findings.append(_finding(
            extension_id,
            version,
            "dangerous-github-workflow",
            "repository-posture",
            "MEDIUM",
            0.66,
            f"GitHub Actions workflow has dangerous supply-chain posture: {rel}.",
            [rel],
            "Review workflow permissions and untrusted pull request execution paths.",
        ))
    has_permissions_block = bool(re.search(r"^permissions:\s*$|^permissions:\s*\S", lowered, re.MULTILINE))
    grants_broad_write = bool(re.search(r"id-token:\s*write", lowered)) and bool(re.search(r"contents:\s*write", lowered))
    uses_github_token = "github_token" in lowered or "secrets.github_token" in lowered
    if grants_broad_write or (uses_github_token and not has_permissions_block):
        findings.append(_finding(
            extension_id,
            version,
            "workflow-token-permissions-broad",
            "repository-posture",
            "LOW",
            0.5,
            f"GitHub Actions workflow {rel} grants broad token permissions or relies on the implicit default token scope.",
            [rel],
            "Declare an explicit least-privilege `permissions:` block scoped to only the jobs that need it.",
        ))


def _artifact_evidence(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"path": str(a["path"]), "sha256": a["sha256"], "size_bytes": a["size_bytes"]}
        for a in artifacts
    ]


def _add_artifact_inventory_findings(
    extension_id: str,
    version: str,
    artifact_inventory: dict[str, Any],
    known_bad_hashes: dict[str, dict[str, Any]],
    findings: list[Finding],
    capabilities: dict[str, dict[str, Any]],
    path: Path | None = None,
) -> None:
    all_paths = {str(entry.get("path")) for entry in artifact_inventory.get("_all_file_hashes", [])}
    packed_artifacts: list[dict[str, Any]] = []
    native_artifacts: list[dict[str, Any]] = []
    for artifact in artifact_inventory["risky_artifacts"]:
        rel = str(artifact["path"])
        kind = str(artifact["kind"])
        if kind == "native":
            native_artifacts.append(artifact)
            capabilities.setdefault("native_code", {"id": "native_code", "evidence": []})["evidence"].append(rel)
            if not _has_origin_evidence(path, rel, all_paths):
                findings.append(_finding(
                    extension_id,
                    version,
                    "binary-without-origin",
                    "provenance",
                    "MEDIUM",
                    0.55,
                    f"Native binary {rel} has no companion checksum or signature file and no documented provenance.",
                    [rel],
                    "Publish a checksum/signature alongside the binary or document its build origin in SECURITY.md/README.",
                    {"sha256": artifact["sha256"]},
                ))
        else:
            packed_artifacts.append(artifact)
            capabilities.setdefault("packed_artifacts", {"id": "packed_artifacts", "evidence": []})["evidence"].append(rel)

    # Emit one aggregate finding per kind rather than one per file. A language
    # server that legitimately ships dozens of jars or native binaries would
    # otherwise flood the report with identical review evidence and read as
    # broken. Scoring is unaffected: component scores use max(), not counts.
    if native_artifacts:
        rels = [str(a["path"]) for a in native_artifacts]
        summary = (
            f"Extension contains a native artifact: {rels[0]}."
            if len(native_artifacts) == 1
            else f"Extension contains {len(native_artifacts)} native artifacts (e.g. {rels[0]})."
        )
        findings.append(_finding(
            extension_id,
            version,
            "native-or-packed-artifact",
            "artifact",
            "MEDIUM",
            0.62,
            summary,
            rels,
            "Confirm the binaries are expected, signed, and published by the same trusted vendor.",
            {"kind": "native", "count": len(native_artifacts), "artifacts": _artifact_evidence(native_artifacts)},
        ))
    if packed_artifacts:
        rels = [str(a["path"]) for a in packed_artifacts]
        summary = (
            f"Extension contains a packed artifact: {rels[0]}."
            if len(packed_artifacts) == 1
            else f"Extension contains {len(packed_artifacts)} packed artifacts (e.g. {rels[0]})."
        )
        findings.append(_finding(
            extension_id,
            version,
            "packed-artifact",
            "provenance",
            "MEDIUM",
            0.58,
            summary,
            rels,
            "Inspect archive contents and verify the packed artifacts are expected and reproducible.",
            {"kind": "packed", "count": len(packed_artifacts), "artifacts": _artifact_evidence(packed_artifacts)},
        ))

    matches = _known_bad_matches(artifact_inventory, known_bad_hashes)
    if matches:
        artifact_inventory["known_bad_matches"] = matches
    for match in matches:
        rel = str(match.get("path") or "package")
        source = str(match.get("source") or "known-bad hash feed")
        findings.append(_finding(
            extension_id,
            version,
            "known-bad-artifact",
            "confirmed-intelligence",
            "CRITICAL",
            0.99,
            f"Artifact hash matches a known-bad entry from {source}.",
            [] if rel == "package" else [rel],
            "Block or remove this extension. A local artifact hash matched confirmed malicious intelligence.",
            match,
        ))


def _has_origin_evidence(path: Path | None, rel: str, all_paths: set[str]) -> bool:
    # All neighboring manifests, checksums, signatures, and documentation are
    # controlled by the extension artifact itself. They are attribution claims,
    # not independent origin verification. Keep review required until an
    # external registry/signature provider verifies the binary against a trust
    # root.
    del path, rel, all_paths
    return False


def _add_code_findings(
    extension_id: str,
    version: str,
    rel: str,
    text: str,
    findings: list[Finding],
    capabilities: dict[str, dict[str, Any]],
) -> None:
    aliased_process_re, aliased_process_methods = _aliased_process_execution(text)
    process_exec_re = re.compile(
        _PROCESS_EXEC_RE.pattern + (f"|{aliased_process_re.pattern}" if aliased_process_re else "")
    )
    process_sink_re = re.compile(
        _EXEC_SINK_RE.pattern + (f"|{aliased_process_re.pattern}" if aliased_process_re else "")
    )
    secret_refs = [(secret_id, label) for secret_id, label, regex in SECRET_PATTERNS if regex.search(text)]
    has_file_read = bool(FILE_READ_RE.search(text))
    has_file_write = bool(FILE_WRITE_RE.search(text))
    has_network = bool(NETWORK_SINK_RE.search(text))
    has_encode = bool(ENCODE_ARCHIVE_RE.search(text))
    has_destructive = bool(DESTRUCTIVE_RE.search(text))
    has_download = bool(DOWNLOAD_RE.search(text))
    has_obfuscation = bool(re.search(r"(atob\(|buffer\.from\([^)]*,\s*['\"]base64['\"]|fromcharcode|\\x[0-9a-f]{2})", text, re.I))
    has_dynamic_exec = bool(_DYNAMIC_EVAL_RE.search(text))
    has_exec_file = bool(re.search(r"\b(?:execFile|execFileSync)\s*\(", text)) or bool(
        aliased_process_methods & {"execFile", "execFileSync"}
    )
    has_shell_exec = bool(_SHELL_EXEC_RE.search(text)) or bool(aliased_process_methods & {"exec", "execSync"})
    has_configured_cli = has_exec_file and bool(re.search(r"getConfiguration\(|config\.get\(|executablePath|cliPath", text))
    has_editor_input = bool(re.search(r"activeTextEditor|document\.getText|selection|workspace\.workspaceFolders|uri\.fsPath|fileName", text))
    has_persistence = bool(re.search(r"(\.bashrc|\.zshrc|\.profile|crontab|launchagents|runonce|scheduledtask|systemd|update_rc|startup\s*folder)", text, re.I))
    # A standalone "mcp" token is common in documentation, error messages, and
    # word lists. Require an actual agent API or protocol identifier before using
    # it as one leg of an exfiltration chain.
    has_agent_surface = bool(re.search(
        r"(?:languageModel|chatParticipant|toolInvocation|invokeTool|mcpServer|@modelcontextprotocol|register(?:Tool|ChatParticipant))",
        text,
        re.I,
    ))
    secret_regex = _combined_secret_regex(secret_refs)

    for rule in CODE_RULES:
        if not rule.regex.search(text):
            continue
        findings.append(_finding(
            extension_id,
            version,
            rule.id,
            rule.category,
            rule.severity,
            rule.confidence,
            rule.summary,
            [rel],
            "Treat this as review evidence unless it combines with credential, network, download, or destructive behavior.",
        ))
        capabilities.setdefault(rule.capability, {"id": rule.capability, "evidence": []})["evidence"].append(rel)

    if aliased_process_re and not any(item.rule_id == "process-execution" and rel in item.file_refs for item in findings):
        findings.append(_finding(
            extension_id,
            version,
            "process-execution",
            "execution",
            "LOW",
            0.7,
            "Code invokes an aliased child_process execution API.",
            [rel],
            "Review the executable, arguments, and input sources passed through the alias.",
            {"methods": sorted(aliased_process_methods), "evidence_class": "weak"},
        ))
        capabilities.setdefault("process_execution", {"id": "process_execution", "evidence": []})["evidence"].append(rel)

    for secret_id, label in secret_refs:
        findings.append(_finding(
            extension_id,
            version,
            f"secret-reference:{secret_id}",
            "credential-access",
            "LOW",
            0.56,
            f"Code references {label}.",
            [rel],
            "Confirm that the extension only reads secrets with explicit user intent and does not transmit them.",
        ))

    # Generated bundles collapse many unrelated modules into one file. Keep
    # high-specificity local flow checks, but do not promote general token
    # proximity across the bundle into correlated evidence.
    if _is_generated_code_blob(rel, text):
        if secret_refs and has_file_read and has_network and _has_direct_credential_network_flow(text, secret_regex):
            findings.append(_finding(
                extension_id,
                version,
                "credential-exfiltration-chain",
                "credential-access",
                "HIGH",
                0.92,
                "A variable assigned from a sensitive local file is used directly as outbound request data.",
                [rel],
                "Remove or block this extension until the direct credential transfer is manually verified.",
                {"evidence_class": "correlated", "correlation": "same-variable-local-flow"},
            ))
        if has_obfuscation and _DECODED_EXECUTION_RE.search(text) and has_network and _features_nearby(text, [
            _DECODED_EXECUTION_RE,
            NETWORK_SINK_RE,
        ]):
            findings.append(_finding(
                extension_id,
                version,
                "obfuscation-execution-network",
                "execution",
                "HIGH",
                0.82,
                "Code combines locally adjacent decoded execution and network behavior.",
                [rel],
                "Treat as suspicious unless the generated dynamic code path is documented and reproducible.",
            ))
        return

    if has_configured_cli and not has_shell_exec and not has_download:
        findings.append(_finding(
            extension_id,
            version,
            "safe-configured-cli-execution",
            "execution",
            "INFO",
            0.72,
            "Code executes a configured local CLI through execFile-style process execution.",
            [rel],
            "Treat as contextual when the binary path is user-configured and arguments are explicit.",
        ))
    if has_shell_exec:
        findings.append(_finding(
            extension_id,
            version,
            "dynamic-shell-execution",
            "execution",
            "MEDIUM",
            0.72,
            "Code uses shell-style process execution.",
            [rel],
            "Review command construction and avoid shell execution for untrusted input.",
        ))
    # Do not infer untrusted-input execution from file-wide token co-occurrence.
    # Editor paths/selections and process APIs commonly share a file in legitimate
    # extensions. The Semgrep taint rule emits untrusted-workspace-input-to-process
    # only when it can establish a source-to-sink flow.

    if secret_refs and has_file_read and _features_nearby(text, [secret_regex, FILE_READ_RE]):
        labels = ", ".join(label for _, label in secret_refs)
        findings.append(_finding(
            extension_id,
            version,
            "credential-file-read",
            "credential-access",
            "MEDIUM",
            0.82,
            f"Code can read local files and references sensitive material: {labels}.",
            [rel],
            "Require a product reason and user-visible flow for reading credential files.",
        ))
    if secret_refs and has_file_read and has_network and _features_nearby(text, [secret_regex, FILE_READ_RE, NETWORK_SINK_RE]):
        findings.append(_finding(
            extension_id,
            version,
            "credential-exfiltration-chain",
            "credential-access",
            "HIGH",
            0.9,
            "Code combines credential references, local file reads, and outbound network writes.",
            [rel],
            "Remove or block this extension until the data flow is manually verified.",
        ))
    if has_destructive and has_encode and has_network and _features_nearby(text, [DESTRUCTIVE_RE, ENCODE_ARCHIVE_RE, NETWORK_SINK_RE]):
        findings.append(_finding(
            extension_id,
            version,
            "destructive-transfer-chain",
            "destructive-activity",
            "HIGH",
            0.84,
            "Code combines destructive file activity with archive/encoding and network behavior.",
            [rel],
            "Treat as suspicious unless this is a clearly documented backup, cleanup, or migration tool.",
        ))
    if has_obfuscation and _DECODED_EXECUTION_RE.search(text) and has_network and _features_nearby(text, [
        _DECODED_EXECUTION_RE,
        NETWORK_SINK_RE,
    ]):
        findings.append(_finding(
            extension_id,
            version,
            "obfuscation-execution-network",
            "execution",
            "HIGH",
            0.82,
            "Code combines obfuscation, dynamic execution, and network behavior.",
            [rel],
            "Treat as suspicious unless the generated or dynamic code path is clearly documented and reproducible.",
        ))
    if has_persistence and has_file_write and (has_network or has_dynamic_exec) and _features_nearby(text, [
        re.compile(r"(\.bashrc|\.zshrc|\.profile|crontab|launchagents|runonce|scheduledtask|systemd|update_rc|startup\s*folder)", re.I),
        FILE_WRITE_RE,
        NETWORK_SINK_RE if has_network else _DYNAMIC_EVAL_RE,
    ]):
        findings.append(_finding(
            extension_id,
            version,
            "persistence-chain",
            "persistence",
            "HIGH",
            0.84,
            "Code appears to modify persistence locations and execute or communicate externally.",
            [rel],
            "Block or manually review persistence behavior in IDE extensions.",
        ))
    if has_agent_surface and secret_refs and has_network and _features_nearby(text, [
        re.compile(r"(?:languageModel|chatParticipant|toolInvocation|invokeTool|mcpServer|@modelcontextprotocol|register(?:Tool|ChatParticipant))", re.I),
        secret_regex,
        NETWORK_SINK_RE,
    ]):
        findings.append(_finding(
            extension_id,
            version,
            "agent-sensitive-data-near-network",
            "agentic",
            "MEDIUM",
            0.68,
            "Agent-facing code contains sensitive references near outbound network behavior.",
            [rel],
            "Review agent tool data boundaries. Proximity alone does not establish that sensitive data reaches the network.",
            {"evidence_class": "exposure", "correlation": "character-proximity"},
        ))
    if has_download and any(item.rule_id == "process-execution" and rel in item.file_refs for item in findings) and _features_nearby(text, [
        DOWNLOAD_RE,
        process_exec_re,
    ]):
        findings.append(_finding(
            extension_id,
            version,
            "download-and-execute",
            "execution",
            "HIGH",
            0.82,
            "Code can download content and execute local processes from the same file.",
            [rel],
            "Verify the download source, integrity checks, and execution purpose.",
        ))
    _add_cross_extension_code_findings(
        extension_id,
        version,
        rel,
        text,
        findings,
        capabilities,
        has_file_write=has_file_write,
        has_network=has_network,
        has_shell_or_dynamic_exec=has_shell_exec or has_dynamic_exec or has_exec_file,
        process_exec_re=process_sink_re,
    )


# Maximum character distance between a credential source surface and a sink for the
# credential-dataflow-to-* correlated rules to fire. Sized to a few source lines: tight
# enough to reject whole-bundle co-occurrence in minified files, loose enough to keep a
# genuinely local capture->exfil sequence. Kept in sync with the _features_nearby budget.
CREDENTIAL_FLOW_WINDOW = 1500

# Obfuscation signal for the obfuscation-execution-network chain. Requires a RUN of at
# least four consecutive \xNN hex escapes (real string-obfuscation) or an explicit base64
# decode. A single \xNN matches benign ANSI terminal color codes (e.g. "\x1B[3...") which
# every CLI-rendering extension contains, so a lone escape must not qualify.
_OBFUSCATION_RE = re.compile(
    r"(?:\\x[0-9a-f]{2}){4,}"
    r"|atob\s*\("
    r"|[Bb]uffer\.from\s*\([^)]*,\s*['\"]base64['\"]",
    re.I,
)

# Verdict-driving native detection requires a direct decode-to-execution shape.
# Merely finding base64 decoding, a process API, and networking near one another
# is common in installers and bundled applications and does not prove execution
# of the decoded bytes. Multi-statement flows are delegated to Semgrep taint.
_DECODED_EXECUTION_RE = re.compile(
    r"(?:\beval\s*\(|new Function\s*\()\s*(?:atob\s*\(|[Bb]uffer\.from\s*\()"
    r"|(?:\beval\s*\(|new Function\s*\()[^)]{0,500}(?:\\x[0-9a-f]{2}){4,}",
    re.I,
)

# Dynamic execution sinks for the obfuscation-execution-network chain: dynamic code
# evaluation (eval / Function constructor / vm) OR real OS-process execution (child_process
# family). Deliberately excludes bare exec(/spawn( standing alone and import() — the former
# match RegExp.prototype.exec()/EventEmitter and unrelated identifiers, the latter matches
# ordinary dynamic ES module imports. spawn(/exec( are only honored when qualified by the
# child_process module or the unambiguous *Sync/*File variants (see _PROCESS_EXEC_RE).
# Real OS-process execution: the child_process module or its unambiguous *Sync/*File
# helpers, plus JVM process APIs. Module imports alone are not execution, and bare
# exec(/spawn( are deliberately excluded — they match RegExp.prototype.exec(),
# EventEmitter.spawn, and any identifier ending in those letters.
_PROCESS_EXEC_RE = re.compile(
    r"(?:\b(?:child_process|cp)\b|require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\))"
    r"\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\("
    r"|\b(?:execSync|execFile|execFileSync|spawnSync)\s*\("
    r"|\bProcessBuilder\b|Runtime\.getRuntime\(\)\.exec"
)

# Dynamic execution used by general correlation rules: dynamic code evaluation
# or an identifiable OS-process call. It intentionally does not match an import
# string, bare exec(), bare spawn(), or ordinary dynamic import().
_DYNAMIC_EVAL_RE = re.compile(
    r"\beval\s*\(|new Function\s*\(|vm\.runIn|vm\.compileFunction\s*\("
    + "|" + _PROCESS_EXEC_RE.pattern
)

# Explicit shell execution. Bare exec() is deliberately excluded because it is
# overwhelmingly RegExp.prototype.exec() in bundled JavaScript. This pattern
# recognizes either the explicit shell option or a direct child_process.exec* call.
_SHELL_EXEC_RE = re.compile(
    r"\bshell\s*:\s*true"
    r"|(?:\b(?:child_process|cp)\b|require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\))\s*\.\s*exec(?:Sync)?\s*\("
)

# Execution sinks for credential-dataflow-to-process: real process execution (above) or
# dynamic code evaluation. Used with a proximity gate against credential source surfaces.
_EXEC_SINK_RE = re.compile(
    _PROCESS_EXEC_RE.pattern + r"|\beval\s*\(|new Function\s*\(|vm\.runIn"
)

_CHILD_PROCESS_METHODS = {"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync"}
_CHILD_PROCESS_DESTRUCTURE_RE = re.compile(
    r"\{(?P<bindings>[^}]{1,500})\}\s*=\s*require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)"
    r"|import\s*\{(?P<imports>[^}]{1,500})\}\s*from\s*['\"](?:node:)?child_process['\"]",
    re.I,
)


def _aliased_process_execution(text: str) -> tuple[re.Pattern[str] | None, set[str]]:
    """Resolve common destructured/ESM child_process aliases that regex qualifiers miss."""
    aliases: dict[str, str] = {}
    for match in _CHILD_PROCESS_DESTRUCTURE_RE.finditer(text):
        bindings = str(match.group("bindings") or match.group("imports") or "")
        for binding in bindings.split(","):
            parts = re.split(r"\s*(?::|\bas\b)\s*", binding.strip(), maxsplit=1, flags=re.I)
            method = parts[0].strip()
            alias = parts[1].strip() if len(parts) == 2 else method
            if method in _CHILD_PROCESS_METHODS and re.fullmatch(r"[A-Za-z_$][\w$]*", alias):
                aliases[alias] = method
    called = {alias: method for alias, method in aliases.items() if re.search(rf"\b{re.escape(alias)}\s*\(", text)}
    if not called:
        return None, set()
    pattern = re.compile(r"\b(?:" + "|".join(re.escape(alias) for alias in sorted(called, key=len, reverse=True)) + r")\s*\(")
    return pattern, set(called.values())

_CLIPBOARD_READ_RE = re.compile(r"(?:env\s*\.\s*)?clipboard\s*\.\s*readText\s*\(")


def _add_cross_extension_code_findings(
    extension_id: str,
    version: str,
    rel: str,
    text: str,
    findings: list[Finding],
    capabilities: dict[str, dict[str, Any]],
    *,
    has_file_write: bool,
    has_network: bool,
    has_shell_or_dynamic_exec: bool,
    process_exec_re: re.Pattern[str],
) -> None:
    sensitive_input = _find_sensitive_api_text(text, r"showInputBox\s*\((?P<args>[^;\n]{0,800})", "InputBox")
    sensitive_config_reads = _find_sensitive_api_text(
        text,
        r"(?:getConfiguration\s*\([^)]*\)\s*\.\s*get|WorkspaceConfiguration\s*\.\s*get|config\s*\.\s*get)\s*\((?P<args>[^;\n]{0,500})",
        "WorkspaceConfiguration",
    )
    sensitive_config_updates = _find_sensitive_api_text(
        text,
        r"(?:getConfiguration\s*\([^)]*\)\s*\.\s*update|WorkspaceConfiguration\s*\.\s*update|config\s*\.\s*update)\s*\((?P<args>[^;\n]{0,500})",
        "WorkspaceConfiguration",
    )
    sensitive_global_state = _find_sensitive_api_text(
        text,
        r"(?:globalState|workspaceState)\s*\.\s*(?:get|update)\s*\((?P<args>[^;\n]{0,500})",
        "GlobalState",
    )
    sensitive_command_register = _find_sensitive_api_text(
        text,
        r"commands\s*\.\s*register(?:TextEditor)?Command\s*\((?P<args>[^;\n]{0,500})",
        "Commands",
    )
    sensitive_command_exec = _find_sensitive_api_text(
        text,
        r"commands\s*\.\s*executeCommand\s*\((?P<args>[^;\n]{0,500})",
        "Commands",
    )
    has_clipboard_read = bool(re.search(r"(?:env\s*\.\s*)?clipboard\s*\.\s*readText\s*\(", text))

    for item in sensitive_input:
        findings.append(_finding(
            extension_id,
            version,
            "credential-inputbox-prompt",
            "cross-extension-exposure",
            "MEDIUM",
            item["confidence"],
            "InputBox prompt or options appear to request credential-related data.",
            [rel],
            "Use VS Code SecretStorage for secret capture and avoid exposing credential prompts to clipboard or command-controlled flows.",
            item,
        ))
        capabilities.setdefault("credential_input", {"id": "credential_input", "evidence": []})["evidence"].append(rel)

    for item in sensitive_config_reads:
        findings.append(_finding(
            extension_id,
            version,
            "credential-config-key",
            "cross-extension-exposure",
            "LOW",
            item["confidence"],
            "Source reads a credential-related VS Code configuration key.",
            [rel],
            "Review whether the setting is world-readable extension configuration and migrate secrets to SecretStorage where possible.",
            item,
        ))

    for item in sensitive_config_updates:
        findings.append(_finding(
            extension_id,
            version,
            "credential-config-update",
            "cross-extension-exposure",
            "HIGH",
            max(0.78, item["confidence"]),
            "Source writes credential-related data to VS Code configuration.",
            [rel],
            "Do not store credentials in VS Code settings; use SecretStorage or an OS credential store.",
            item,
        ))

    for item in sensitive_global_state:
        rule_id = "credential-global-state-storage" if ".update" in item.get("snippet", "") else "credential-global-state-key"
        findings.append(_finding(
            extension_id,
            version,
            rule_id,
            "cross-extension-exposure",
            "HIGH" if rule_id == "credential-global-state-storage" else "LOW",
            max(0.76, item["confidence"]) if rule_id == "credential-global-state-storage" else item["confidence"],
            "Source uses a credential-related globalState/workspaceState key.",
            [rel],
            "Avoid storing credentials in extension state unless access boundaries and lifetime are explicitly understood.",
            item,
        ))

    for item in sensitive_command_register:
        findings.append(_finding(
            extension_id,
            version,
            "credential-command-registration",
            "cross-extension-exposure",
            "LOW",
            item["confidence"],
            "Source registers a credential-related command surface.",
            [rel],
            "Review whether other extensions can invoke this command and whether credential access requires explicit user intent.",
            item,
        ))

    for item in sensitive_command_exec:
        findings.append(_finding(
            extension_id,
            version,
            "credential-command-execution",
            "cross-extension-exposure",
            "MEDIUM",
            max(0.68, item["confidence"]),
            "Source executes a credential-related VS Code command.",
            [rel],
            "Review command control paths and avoid allowing untrusted extensions or inputs to steer credential operations.",
            item,
        ))

    has_sensitive_source = bool(sensitive_input or sensitive_config_reads or sensitive_config_updates or sensitive_global_state)
    # Character offsets of every sensitive credential source surface in this file. The
    # dataflow-to-* rules below require a sink to sit within CREDENTIAL_FLOW_WINDOW chars
    # of one of these sources. Without this, minified bundles (entire program in one file)
    # trivially satisfy "source and sink in the same file" and every legitimate bundled
    # extension is flagged CRITICAL. Proximity is a weak proxy for dataflow, but it rejects
    # the whole-bundle co-occurrence that produced the false positives.
    _sensitive_source_positions = [
        item["pos"]
        for group in (sensitive_input, sensitive_config_reads, sensitive_config_updates, sensitive_global_state)
        for item in group
        if isinstance(item.get("pos"), int)
    ]

    def _sink_near_credential_source(sink_pattern: "re.Pattern[str]") -> bool:
        if not _sensitive_source_positions:
            return False
        for match in sink_pattern.finditer(text):
            sink_pos = match.start()
            if any(abs(sink_pos - src) <= CREDENTIAL_FLOW_WINDOW for src in _sensitive_source_positions):
                return True
        return False

    def _surfaces_nearby(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> bool:
        return any(
            isinstance(a.get("pos"), int)
            and isinstance(b.get("pos"), int)
            and abs(a["pos"] - b["pos"]) <= CREDENTIAL_FLOW_WINDOW
            for a in left
            for b in right
        )

    if sensitive_input and sensitive_global_state and _surfaces_nearby(sensitive_input, sensitive_global_state):
        findings.append(_finding(
            extension_id,
            version,
            "credential-input-near-state",
            "cross-extension-exposure",
            "HIGH",
            0.82,
            "Credential-like user input appears near extension state storage.",
            [rel],
            "Manually verify whether credential input can be stored in cross-extension-accessible state or command-controlled flows.",
            {"surfaces": ["InputBox", "GlobalState"], "evidence_class": "exposure", "correlation": "character-proximity"},
        ))
    if has_clipboard_read and has_sensitive_source and _sink_near_credential_source(_CLIPBOARD_READ_RE):
        findings.append(_finding(
            extension_id,
            version,
            "clipboard-near-credential-surface",
            "cross-extension-exposure",
            "HIGH",
            0.8,
            "Clipboard reads appear in the same file as credential-related input or storage surfaces.",
            [rel],
            "Avoid reading clipboard contents around secret capture flows unless the user explicitly requested the paste/import action.",
            {"surfaces": ["clipboard", "credential"], "evidence_class": "exposure", "correlation": "character-proximity"},
        ))
    if has_sensitive_source and has_network and _sink_near_credential_source(NETWORK_SINK_RE):
        findings.append(_finding(
            extension_id,
            version,
            "credential-source-near-network",
            "cross-extension-exposure",
            "HIGH",
            0.74,
            "A credential-related source surface appears near a network sink.",
            [rel],
            "Review the cited code. Character proximity does not establish that credential data reaches the sink.",
            {"sink": "network", "evidence_class": "exposure", "correlation": "character-proximity"},
        ))
    if has_sensitive_source and has_shell_or_dynamic_exec and _sink_near_credential_source(process_exec_re):
        findings.append(_finding(
            extension_id,
            version,
            "credential-source-near-process",
            "cross-extension-exposure",
            "HIGH",
            0.7,
            "A credential-related source surface appears near process execution.",
            [rel],
            "Manually verify whether credentials can influence process execution or command arguments.",
            {"sink": "process", "evidence_class": "exposure", "correlation": "character-proximity"},
        ))
    if has_sensitive_source and has_file_write and _sink_near_credential_source(FILE_WRITE_RE):
        findings.append(_finding(
            extension_id,
            version,
            "credential-source-near-file",
            "cross-extension-exposure",
            "HIGH",
            0.68,
            "A credential-related source surface appears near a file write.",
            [rel],
            "Review file persistence paths and ensure raw secrets are not written to workspace or extension files.",
            {"sink": "file", "evidence_class": "exposure", "correlation": "character-proximity"},
        ))


def _find_sensitive_api_text(text: str, pattern: str, surface: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in re.finditer(pattern, text, re.I | re.S):
        snippet = _balanced_call_arguments(text, match.start("args")) if "args" in match.groupdict() else match.group(0)
        if not _looks_sensitive_text(snippet):
            continue
        out.append({
            "surface": surface,
            "text": _truncate_evidence_text(snippet),
            "snippet": _truncate_evidence_text(match.group(0)),
            "confidence": _sensitive_text_confidence(snippet, base=0.64),
            "pos": match.start(),
        })
    return out[:10]


def _balanced_call_arguments(text: str, start: int) -> str:
    """Return only the matched call's arguments, including minified source.

    Regex ranges that stop at a semicolon or newline can cross several comma-
    chained expressions in generated bundles. This small lexical boundary
    keeps credential terms in a neighboring call from contaminating the
    surface being classified.
    """
    depth = 1
    quote = ""
    escaped = False
    for index in range(start, min(len(text), start + 4000)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start:index]
    return text[start:min(len(text), start + 500)]


def _has_direct_credential_network_flow(text: str, secret_pattern: re.Pattern[str]) -> bool:
    assignment = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,1200})")
    for match in assignment.finditer(text):
        expression = match.group(2)
        if not FILE_READ_RE.search(expression) or not secret_pattern.search(expression):
            continue
        variable = re.escape(match.group(1))
        tail = text[match.end():min(len(text), match.end() + 3000)]
        if not NETWORK_SINK_RE.search(tail):
            continue
        if re.search(rf"(?:body\s*:\s*{variable}\b|(?:write|send|post)\s*\(\s*{variable}\b)", tail):
            return True
    return False


def _manifest_configuration_items(contributes: dict[str, Any]) -> list[dict[str, Any]]:
    configuration = contributes.get("configuration")
    blocks = configuration if isinstance(configuration, list) else [configuration]
    items: list[dict[str, Any]] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        properties = block.get("properties")
        if not isinstance(properties, dict):
            continue
        for key, value in properties.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            item = dict(value)
            item["key"] = key
            item.setdefault("title", block.get("title", ""))
            items.append(item)
    return items


def _manifest_commands(contributes: dict[str, Any]) -> list[dict[str, Any]]:
    commands = contributes.get("commands")
    if not isinstance(commands, list):
        return []
    return [dict(item) for item in commands if isinstance(item, dict)]


def _looks_sensitive_text(value: str) -> bool:
    if not value or SENSITIVE_TEXT_NEGATIVE_RE.search(value):
        return False
    return bool(SENSITIVE_TEXT_RE.search(value))


def _sensitive_text_confidence(value: str, *, base: float) -> float:
    text = value.lower()
    confidence = base
    if re.search(r"(api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|client[-_ ]?secret|private[-_ ]?key)", text):
        confidence += 0.14
    if re.search(r"(openai|anthropic|claude|github|npm|aws|azure|gemini)", text):
        confidence += 0.08
    if SENSITIVE_TEXT_NEGATIVE_RE.search(text):
        confidence -= 0.18
    return round(max(0.35, min(0.94, confidence)), 2)


def _truncate_evidence_text(value: str, limit: int = 240) -> str:
    compact = re.sub(r"\s+", " ", str(value)).strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _combined_secret_regex(secret_refs: list[tuple[str, str]]) -> re.Pattern[str]:
    if not secret_refs:
        return re.compile(r"a\Ab")
    patterns = [
        regex.pattern
        for secret_id, _, regex in SECRET_PATTERNS
        if any(secret_id == found_id for found_id, _ in secret_refs)
    ]
    return re.compile("|".join(f"(?:{pattern})" for pattern in patterns), re.I)


def _features_nearby(text: str, patterns: list[re.Pattern[str]], window_lines: int = 45) -> bool:
    # Proximity is measured in CHARACTER offsets, not line indices. Minified/bundled
    # extensions pack the entire program onto a handful of enormous lines (mean ~900+
    # chars/line, single lines over 100k chars), so a line-index window degenerates into
    # "these features exist somewhere in the same multi-megabyte file" and fires the
    # correlated chains on every legitimate bundled extension. A genuine exfil/execute
    # chain is locally adjacent; scattered features across a huge bundle are not.
    if not patterns:
        return False
    # ~72 chars/line is a generous upper bound for hand-written code, so the character
    # budget stays behaviorally equivalent to the old line window on non-minified files
    # while remaining tight on minified bundles.
    window_chars = max(window_lines * 72, 240)
    anchors = [match.start() for match in patterns[0].finditer(text)]
    if not anchors:
        return False
    for anchor in anchors:
        start = max(0, anchor - window_chars)
        end = min(len(text), anchor + window_chars)
        if all((match := pattern.search(text, start)) is not None and match.start() <= end for pattern in patterns[1:]):
            return True
    return False


WEBVIEW_SURFACE_RE = re.compile(r"createWebviewPanel\(|registerWebviewViewProvider\(|\.webview\.html\s*=", re.I)
CSP_META_RE = re.compile(r"<meta[^>]+http-equiv\s*=\s*[\"']Content-Security-Policy[\"'][^>]*>", re.I)
CSP_UNSAFE_DIRECTIVE_RE = re.compile(r"unsafe-inline|unsafe-eval|script-src[^;\"']*\*", re.I)


def _add_webview_csp_findings(
    extension_id: str,
    version: str,
    rel: str,
    text: str,
    findings: list[Finding],
    *,
    report_missing: bool = True,
) -> None:
    if not WEBVIEW_SURFACE_RE.search(text):
        return
    csp_match = CSP_META_RE.search(text)
    if not csp_match and report_missing:
        findings.append(_finding(
            extension_id,
            version,
            "webview-csp-missing",
            "webview",
            "MEDIUM",
            0.6,
            f"Extension creates a webview in {rel} without a detected Content-Security-Policy meta tag.",
            [rel],
            "Add a strict Content-Security-Policy meta tag to every webview HTML document, scoping script-src/style-src to the webview's own origin and the webview.cspSource.",
        ))
        return
    if not csp_match:
        return
    if CSP_UNSAFE_DIRECTIVE_RE.search(csp_match.group(0)):
        findings.append(_finding(
            extension_id,
            version,
            "webview-csp-unsafe-directive",
            "webview",
            "MEDIUM",
            0.58,
            f"Extension webview in {rel} declares a Content-Security-Policy with an unsafe directive (unsafe-inline, unsafe-eval, or a wildcard script-src).",
            [rel],
            "Avoid unsafe-inline, unsafe-eval, and wildcard script-src in webview CSP; use nonces or content hashes instead.",
        ))


def _apply_registry_findings(extensions: list[ExtensionReport], raw_findings: list[dict[str, Any]]) -> None:
    by_id = {extension.extension_id: extension for extension in extensions}
    for raw in raw_findings:
        extension = by_id.get(str(raw.get("extension_id")))
        if extension is None:
            continue
        finding = _finding(
            extension.extension_id,
            extension.version,
            str(raw["rule_id"]),
            str(raw["category"]),
            str(raw["severity"]),
            float(raw["confidence"]),
            str(raw["evidence_summary"]),
            [],
            "Use registry evidence as high-confidence supply-chain signal and remove the extension if malicious.",
            _evidence_with_class(str(raw["rule_id"]), raw.get("evidence")),
        )
        extension.findings.append(finding)
        extension.severity = rank_severity(extension.severity, finding.severity)
        extension.risk_score = max(extension.risk_score, finding.score)
        if _is_confirmed_malware_finding(finding):
            extension.verdict = "malicious"
            extension.verdict_reason = "Confirmed registry or malicious-package evidence matched this extension."
            extension.malware_score = max(extension.malware_score, 95)
            extension.risk_score = max(extension.risk_score, 95)
        elif _is_suspicious_removed_finding(finding) and extension.verdict in {"clean", "review"}:
            extension.verdict = "suspicious"
            extension.verdict_reason = "Marketplace removal evidence says this extension was removed as suspicious."
        elif finding.severity == "HIGH" and extension.verdict == "clean":
            extension.verdict = "suspicious"
            extension.verdict_reason = "Dependency registry evidence produced a high-confidence vulnerability signal."
        elif extension.verdict == "clean" and _evidence_class(str(raw["rule_id"]), raw.get("evidence")) != "reputation":
            extension.verdict = "review"
            extension.verdict_reason = "Registry evidence found dependency risk that needs review."
        (
            extension.verdict,
            extension.verdict_reason,
            extension.malware_authority,
            extension.severity,
            extension.malware_score,
            extension.risk_score,
            extension.score_details,
        ) = _classify_findings(extension.findings)


def _apply_sandbox_observations(extensions: list[ExtensionReport], observations: dict[str, list[dict[str, Any]]]) -> None:
    if not observations:
        return
    by_id = {extension.extension_id: extension for extension in extensions}
    for extension_id, items in observations.items():
        extension = by_id.get(extension_id)
        if extension is None:
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            finding = _sandbox_observation_finding(extension, item)
            if finding is None:
                continue
            extension.findings.append(finding)
        (
            extension.verdict,
            extension.verdict_reason,
            extension.malware_authority,
            extension.severity,
            extension.malware_score,
            extension.risk_score,
            extension.score_details,
        ) = _classify_findings(extension.findings)


def _apply_threat_feed(extensions: list[ExtensionReport], feed: dict[str, dict[str, Any]]) -> None:
    if not feed:
        return
    by_id = {extension.extension_id.lower(): extension for extension in extensions}
    for extension_id, metadata in feed.items():
        extension = by_id.get(extension_id.lower())
        if extension is None:
            continue
        classification = str(metadata.get("classification") or metadata.get("verdict") or "").lower()
        malicious = classification in {"malware", "malicious"}
        severity = "CRITICAL" if malicious else "HIGH"
        rule_id = "trusted-threat-feed-hit" if malicious else "marketplace-removed-package"
        evidence = dict(metadata)
        evidence.setdefault("extension_id", extension.extension_id)
        evidence.setdefault("type", classification or "suspicious")
        finding = _finding(
            extension.extension_id,
            extension.version,
            rule_id,
            "confirmed-intelligence" if malicious else "provenance",
            severity,
            0.97 if malicious else 0.82,
            f"Extension matched configured threat feed as {classification or 'suspicious'}.",
            [],
            "Block malware feed hits. Review non-malware feed hits according to source confidence.",
            evidence,
        )
        extension.findings.append(finding)
        (
            extension.verdict,
            extension.verdict_reason,
            extension.malware_authority,
            extension.severity,
            extension.malware_score,
            extension.risk_score,
            extension.score_details,
        ) = _classify_findings(extension.findings)


def _load_threat_feed(path: Path | str | None = None) -> dict[str, dict[str, Any]]:
    raw_path = str(path or os.environ.get("IDE_SCANNER_THREAT_FEED_FILE") or "")
    if not raw_path:
        return {}
    try:
        parsed = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    entries = parsed.get("extensions") if isinstance(parsed, dict) else parsed
    out: dict[str, dict[str, Any]] = {}
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            extension_id = str(entry.get("extension_id") or entry.get("id") or "").strip()
            if extension_id:
                out[extension_id] = dict(entry)
    elif isinstance(entries, dict):
        for extension_id, metadata in entries.items():
            if isinstance(extension_id, str):
                out[extension_id] = dict(metadata) if isinstance(metadata, dict) else {"classification": str(metadata)}
    return out


def _load_extension_advisories(path: Path | str | None = None) -> dict[str, Any]:
    default_path = Path(__file__).parent / "intelligence" / "extension-advisories.json"
    raw_path = Path(path or os.environ.get("IDE_SCANNER_EXTENSION_ADVISORIES_FILE") or default_path)
    try:
        raw = raw_path.read_bytes()
        parsed = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return {"status": "unavailable", "snapshot_version": "unavailable", "sha256": "", "entries": []}
    if not isinstance(parsed, dict) or not isinstance(parsed.get("entries"), list):
        return {"status": "invalid", "snapshot_version": "invalid", "sha256": hashlib.sha256(raw).hexdigest(), "entries": []}
    return {
        "status": "completed",
        "snapshot_version": str(parsed.get("snapshot_version") or "unknown"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "entries": [entry for entry in parsed["entries"] if isinstance(entry, dict)],
    }


def _apply_extension_advisories(extensions: list[ExtensionReport], bundle: dict[str, Any]) -> None:
    for extension in extensions:
        for entry in bundle.get("entries") or []:
            if str(entry.get("extension_id") or "").lower() != extension.extension_id.lower():
                continue
            if str(entry.get("version") or "") != extension.version:
                continue
            expected_hash = str(entry.get("artifact_sha256") or "").lower()
            if len(expected_hash) != 64 or expected_hash != extension.artifact_hash.lower():
                continue
            severity = str(entry.get("severity") or "HIGH").upper()
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                severity = "HIGH"
            evidence = dict(entry)
            evidence.update({
                "evidence_class": "vulnerability",
                "snapshot_version": str(bundle.get("snapshot_version") or "unknown"),
                "snapshot_sha256": str(bundle.get("sha256") or ""),
                "exact": True,
            })
            extension.findings.append(_finding(
                extension.extension_id,
                extension.version,
                "known-vulnerable-extension",
                "vulnerability",
                severity,
                0.98,
                str(entry.get("summary") or "Exact extension artifact matched a vulnerability advisory."),
                [],
                "Follow the linked advisory and reject the exact artifact when policy_action is block.",
                evidence,
            ))
        (
            extension.verdict,
            extension.verdict_reason,
            extension.malware_authority,
            extension.severity,
            extension.malware_score,
            extension.risk_score,
            extension.score_details,
        ) = _classify_findings(extension.findings)


def _sandbox_observation_finding(extension: ExtensionReport, item: dict[str, Any]) -> Finding | None:
    kind = str(item.get("kind") or item.get("type") or item.get("rule_id") or "").strip()
    mapping = {
        "secret_read": ("observed-secret-read", "MEDIUM", 0.78, "Sandbox observed reads of canary or sensitive credential paths."),
        "secret_exfil": ("observed-secret-exfil", "HIGH", 0.9, "Sandbox observed canary or sensitive data leaving the process."),
        "download_execute": ("observed-download-execute", "HIGH", 0.86, "Sandbox observed downloaded content being executed or loaded."),
        "persistence": ("observed-persistence", "HIGH", 0.84, "Sandbox observed persistence or autorun behavior."),
        "destructive": ("observed-destructive-behavior", "HIGH", 0.88, "Sandbox observed destructive file behavior."),
        "unexpected_network": ("observed-unexpected-network", "MEDIUM", 0.68, "Sandbox observed network traffic to an unexpected destination."),
        "process_exec": ("observed-process-exec", "MEDIUM", 0.66, "Sandbox observed process execution."),
        "filesystem_write": ("observed-filesystem-write", "LOW", 0.58, "Sandbox observed filesystem writes."),
    }
    if kind not in mapping:
        return None
    rule_id, severity, confidence, summary = mapping[kind]
    evidence = dict(item)
    evidence["evidence_class"] = "observed"
    file_refs = [str(ref) for ref in item.get("file_refs", [])] if isinstance(item.get("file_refs"), list) else []
    return _finding(
        extension.extension_id,
        extension.version,
        rule_id,
        "dynamic-sandbox",
        severity,
        confidence,
        summary,
        file_refs,
        "Review the sandbox trace. Dynamic observations are strong evidence but not authoritative malware without confirmed intelligence.",
        evidence,
    )


def _load_sandbox_observations(path: Path | str | None = None) -> dict[str, list[dict[str, Any]]]:
    raw_path = str(path or os.environ.get("IDE_SCANNER_SANDBOX_OBSERVATIONS_FILE") or "")
    if not raw_path:
        return {}
    try:
        parsed = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(parsed, dict) and isinstance(parsed.get("extensions"), dict):
        parsed = parsed["extensions"]
    if not isinstance(parsed, dict):
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for extension_id, items in parsed.items():
        if isinstance(extension_id, str) and isinstance(items, list):
            out[extension_id] = [item for item in items if isinstance(item, dict)]
    return out


def _build_report(
    extensions: list[ExtensionReport],
    registry: dict[str, Any],
    previous_report: dict[str, Any] | None = None,
    include_posture: bool = True,
    intelligence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    version_deltas = _version_deltas(extensions, previous_report)
    deltas_by_id = {str(item.get("extension_id")): item for item in version_deltas}
    for extension in extensions:
        extension.baseline_diff = dict(deltas_by_id.get(extension.extension_id) or {})
        _apply_security_decision(extension)

    by_verdict: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_decision: dict[str, int] = {}
    max_score = 0
    max_malware_score = 0
    max_risk_score = 0
    for extension in extensions:
        by_verdict[extension.verdict] = by_verdict.get(extension.verdict, 0) + 1
        by_severity[extension.severity] = by_severity.get(extension.severity, 0) + 1
        by_decision[extension.decision] = by_decision.get(extension.decision, 0) + 1
        max_malware_score = max(max_malware_score, extension.malware_score)
        max_risk_score = max(max_risk_score, extension.risk_score)
        max_score = max(max_score, extension.risk_score)

    now = dt.datetime.now(dt.UTC)
    if include_posture:
        posture_metrics = scan_posture()
        posture_summary = summarize_posture(posture_metrics)
    else:
        posture_metrics = []
        posture_summary = _skipped_posture_summary()
    summary = {
        "total_extensions": len(extensions),
        "by_verdict": by_verdict,
        "by_severity": by_severity,
        "by_decision": by_decision,
        "max_score": max_score,
        "max_malware_score": max_malware_score,
        "max_risk_score": max_risk_score,
        "posture_score": posture_summary["score"],
        "posture_status": posture_summary["status"],
    }
    return {
        "schema_version": "0.1.0",
        "scan_id": f"scan_{now.strftime('%Y%m%d%H%M%S')}",
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "scanner_build": os.environ.get("IDE_SCANNER_BUILD_SHA", "").strip() or "unknown",
        "ruleset_version": RULESET_VERSION,
        "policy_version": POLICY_VERSION,
        "privacy_mode": "local-metadata-and-static-features",
        "registry_checks": registry,
        "intelligence": dict(intelligence or {}),
        "summary": summary,
        "human_summary": _human_summary(summary, extensions, registry, version_deltas, posture_summary if include_posture else None),
        "version_deltas": version_deltas,
        "posture_summary": posture_summary,
        "posture": [metric.to_dict() for metric in posture_metrics],
        "extensions": [extension.to_dict() for extension in extensions],
    }


def _skipped_posture_summary() -> dict[str, Any]:
    return {
        "status": "skipped",
        "score": 0,
        "max_metric_score": 0,
        "weighted_score": 0,
        "counts": {
            "failure": 0,
            "warning": 0,
            "success": 0,
            "skipped": 0,
        },
        "clients": [],
        "total_metrics": 0,
        "top_findings": [],
    }


def _human_summary(
    summary: dict[str, Any],
    extensions: list[ExtensionReport],
    registry: dict[str, Any],
    version_deltas: list[dict[str, Any]],
    posture_summary: dict[str, Any] | None = None,
) -> list[str]:
    by_verdict = summary.get("by_verdict", {})
    notes = [
        f"Scanned {summary.get('total_extensions', 0)} extension(s): "
        f"{by_verdict.get('malicious', 0)} malicious, "
        f"{by_verdict.get('suspicious', 0)} suspicious, "
        f"{by_verdict.get('review', 0)} review, "
        f"{by_verdict.get('clean', 0)} clean."
    ]
    if registry.get("enabled"):
        notes.append(
            f"Online registry checks returned {len(registry.get('findings', []))} finding(s) "
            f"and {len(registry.get('errors', []))} error(s)."
        )
    if posture_summary:
        counts = posture_summary.get("counts", {})
        notes.append(
            f"IDE/client posture: {posture_summary.get('status', 'unknown')} "
            f"with score {posture_summary.get('score', 0)}/100 "
            f"({counts.get('failure', 0)} failures, {counts.get('warning', 0)} warnings)."
        )
    top = sorted(extensions, key=lambda item: (item.malware_score, item.risk_score), reverse=True)[:3]
    if top:
        notes.append("Highest-priority items: " + "; ".join(
            f"{item.extension_id}={item.verdict}/M{item.malware_score}/R{item.risk_score}"
            for item in top
        ))
    if version_deltas:
        notes.append(f"Compared with previous report: {len(version_deltas)} extension(s) changed version, score, dependency, or artifact inventory.")
    return notes


def _load_previous_report(path: Path | str | None) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _version_deltas(extensions: list[ExtensionReport], previous_report: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not previous_report:
        return []
    previous_extensions = previous_report.get("extensions")
    if not isinstance(previous_extensions, list):
        return []
    by_id = {
        str(item.get("extension_id")): item
        for item in previous_extensions
        if isinstance(item, dict) and item.get("extension_id")
    }
    deltas: list[dict[str, Any]] = []
    for extension in extensions:
        previous = by_id.get(extension.extension_id)
        if not previous:
            continue
        delta: dict[str, Any] = {
            "extension_id": extension.extension_id,
            "previous_version": previous.get("version"),
            "current_version": extension.version,
            "changes": [],
        }
        if previous.get("version") != extension.version:
            delta["changes"].append("version")
        if previous.get("verdict") != extension.verdict:
            delta["changes"].append("verdict")
        if int(previous.get("risk_score") or 0) != extension.risk_score:
            delta["changes"].append("risk_score")
        if int(previous.get("malware_score") or 0) != extension.malware_score:
            delta["changes"].append("malware_score")
        previous_identity = previous.get("artifact_identity") if isinstance(previous.get("artifact_identity"), dict) else {}
        previous_hash = str(previous.get("artifact_hash") or previous_identity.get("sha256") or "")
        exact_hash_changed = len(previous_hash) == 64 and len(extension.artifact_hash) == 64 and previous_hash != extension.artifact_hash
        artifact_changed = previous.get("version") != extension.version or exact_hash_changed
        delta["artifact_changed"] = artifact_changed
        if exact_hash_changed:
            delta["changes"].append("artifact_hash")
        previous_deps = set((previous.get("dependencies") or {}).keys()) if isinstance(previous.get("dependencies"), dict) else set()
        current_deps = set(extension.dependencies.keys())
        added_deps = sorted(current_deps - previous_deps)
        removed_deps = sorted(previous_deps - current_deps)
        if added_deps or removed_deps:
            delta["changes"].append("dependencies")
            delta["added_dependencies"] = added_deps[:25]
            delta["removed_dependencies"] = removed_deps[:25]
        previous_artifacts = _artifact_paths(previous)
        current_artifacts = {str(item.get("path")) for item in extension.artifact_inventory.get("risky_artifacts", []) if isinstance(item, dict)}
        added_artifacts = sorted(current_artifacts - previous_artifacts)
        removed_artifacts = sorted(previous_artifacts - current_artifacts)
        if added_artifacts or removed_artifacts:
            delta["changes"].append("risky_artifacts")
            delta["added_risky_artifacts"] = added_artifacts[:25]
            delta["removed_risky_artifacts"] = removed_artifacts[:25]
        previous_rules = {
            str(item.get("rule_id")) for item in previous.get("findings") or []
            if isinstance(item, dict) and item.get("rule_id")
        }
        current_rules = {finding.rule_id for finding in extension.findings}
        added_rules = sorted(current_rules - previous_rules)
        removed_rules = sorted(previous_rules - current_rules)
        if added_rules or removed_rules:
            delta["changes"].append("findings")
            delta["added_findings"] = added_rules[:50]
            delta["removed_findings"] = removed_rules[:50]
        previous_capabilities = {
            str(item.get("id")) for item in previous.get("capabilities") or []
            if isinstance(item, dict) and item.get("id")
        }
        current_capabilities = {
            str(item.get("id")) for item in extension.capabilities
            if isinstance(item, dict) and item.get("id")
        }
        added_capabilities = sorted(current_capabilities - previous_capabilities)
        removed_capabilities = sorted(previous_capabilities - current_capabilities)
        if added_capabilities or removed_capabilities:
            delta["changes"].append("capabilities")
            delta["added_capabilities"] = added_capabilities[:50]
            delta["removed_capabilities"] = removed_capabilities[:50]
        if delta["changes"]:
            delta["analysis_changed"] = True
            delta["baseline_changed"] = artifact_changed
            deltas.append(delta)
    return deltas


def _apply_security_decision(extension: ExtensionReport) -> None:
    coverage = extension.analysis_coverage or extension.artifact_inventory.get("analysis_coverage") or {}
    incomplete = bool(extension.artifact_inventory.get("scan_incomplete")) or coverage.get("status") == "incomplete"
    extension.analysis_status = _analysis_status(extension, coverage, incomplete)
    if extension.verdict == "malicious":
        extension.decision = "block"
        extension.decision_reason = "Confirmed malicious intelligence or an exact known-bad artifact matched."
        return
    if incomplete:
        extension.decision = "incomplete"
        extension.decision_reason = str(extension.artifact_inventory.get("skipped_reason") or "Executable analysis did not complete.")
        return
    blocking_rule_ids = _preventive_blocking_rule_ids(extension.findings)
    vulnerability_blocks = {
        finding.rule_id for finding in extension.findings
        if finding_actionability(finding) == "block" and _finding_evidence_class(finding) == "vulnerability"
    }
    if vulnerability_blocks:
        extension.decision = "block"
        extension.decision_reason = (
            "Reject this exact artifact: authoritative vulnerability intelligence matched "
            f"({', '.join(sorted(vulnerability_blocks))}). This is a vulnerability policy decision, not a malware label."
        )
        return
    if blocking_rule_ids:
        extension.decision = "block"
        extension.decision_reason = (
            "Prevent execution pending review: high-confidence abuse-chain evidence matched "
            f"({', '.join(sorted(blocking_rule_ids))}). This is a preventive policy decision, not a confirmed-malicious label."
        )
        return
    added_capabilities = list(extension.baseline_diff.get("added_capabilities") or [])
    added_findings = list(extension.baseline_diff.get("added_findings") or [])
    artifact_changed = bool(extension.baseline_diff.get("artifact_changed"))
    if extension.verdict in {"suspicious", "review"} or (artifact_changed and (added_capabilities or added_findings)):
        extension.decision = "review"
        if artifact_changed and (added_capabilities or added_findings):
            extension.decision_reason = "The artifact changed from its baseline and introduced new security-relevant behavior."
        else:
            extension.decision_reason = extension.verdict_reason
        return
    extension.decision = "allow"
    extension.decision_reason = "Analysis completed without actionable evidence or unapproved baseline changes."


def _analysis_status(extension: ExtensionReport, coverage: dict[str, Any], incomplete: bool) -> str:
    if not incomplete and coverage.get("status") == "complete":
        return "complete"
    providers = coverage.get("providers") if isinstance(coverage.get("providers"), dict) else {}
    acquisition = providers.get("artifact_acquisition") if isinstance(providers, dict) else None
    manifest = coverage.get("manifest_validation") if isinstance(coverage.get("manifest_validation"), dict) else {}
    if (
        extension.source == "marketplace-error"
        or (isinstance(acquisition, dict) and acquisition.get("status") == "failed")
        or manifest.get("status") == "scan-aborted"
    ):
        return "failed"
    return "incomplete"


def _preventive_blocking_rule_ids(findings: list[Finding]) -> set[str]:
    """Return behavior rules strong enough to prevent execution without threat intelligence.

    Generic download-and-execute behavior is intentionally insufficient by itself:
    legitimate language servers and tool installers can look similar. It becomes a
    preventive block only when automatic activation and credential handling occur in
    the same extension. Confirmed intelligence is handled separately by verdict.
    """
    rule_ids = {finding.rule_id for finding in findings}
    blocking = rule_ids & (BLOCKING_CORRELATED_RULES | BLOCKING_OBSERVED_RULES)
    credential_signal = bool(rule_ids & DOWNLOAD_EXECUTE_CREDENTIAL_SIGNALS) or any(
        rule_id.startswith("secret-reference:") for rule_id in rule_ids
    )
    automatic_activation = bool(rule_ids & {"broad-activation", "startup-activation", "sensitive-activation"})
    if "download-and-execute" in rule_ids and credential_signal and automatic_activation:
        blocking.add("download-and-execute")
    return blocking


def _artifact_paths(extension: dict[str, Any]) -> set[str]:
    inventory = extension.get("artifact_inventory")
    if not isinstance(inventory, dict):
        return set()
    artifacts = inventory.get("risky_artifacts")
    if not isinstance(artifacts, list):
        return set()
    return {str(item.get("path")) for item in artifacts if isinstance(item, dict)}


def _empty_artifact_inventory() -> dict[str, Any]:
    return {
        "hash_algorithm": "sha256",
        "package_hash": "",
        "files_hashed": 0,
        "total_bytes_hashed": 0,
        "risky_artifacts": [],
        "known_bad_matches": [],
        "vsix_signature": {"present": False, "verified": False, "verification_supported": False, "reason": "not-vsix"},
        "_all_file_hashes": [],
    }


def _vsix_signature_status(root: Path) -> dict[str, Any]:
    signature_files = [
        item.relative_to(root).as_posix()
        for item in root.rglob("*")
        if item.is_file() and (
            item.name.lower().endswith((".signature.p7s", ".sig", ".p7s"))
            or item.relative_to(root).as_posix().lower().startswith("meta-inf/")
        )
    ]
    return {
        "present": bool(signature_files),
        "verified": False,
        "verification_supported": False,
        "reason": (
            "signature-file-present-but-not-cryptographically-verified"
            if signature_files
            else "no-signature-file-found"
        ),
        "files": signature_files[:10],
    }


def _artifact_inventory(path: Path, files: list[Path]) -> dict[str, Any]:
    inventory = _empty_artifact_inventory()
    package_digest = hashlib.sha256()
    all_hashes: list[dict[str, Any]] = []
    risky_artifacts: list[dict[str, Any]] = []
    total_bytes = 0

    for file in sorted(files):
        rel = file.relative_to(path).as_posix()
        if file.is_symlink():
            try:
                target = os.readlink(file)
            except OSError:
                target = "unreadable"
            digest = hashlib.sha256(target.encode("utf-8", errors="replace")).hexdigest()
            size = len(target.encode("utf-8", errors="replace"))
            all_hashes.append({"path": rel, "sha256": digest, "size_bytes": size, "kind": "symlink", "target": target})
            risky_artifacts.append({"path": rel, "sha256": digest, "size_bytes": size, "kind": "symlink", "target": target})
            package_digest.update(rel.encode("utf-8"))
            package_digest.update(b"\0symlink\0")
            package_digest.update(target.encode("utf-8", errors="replace"))
            package_digest.update(b"\0")
            continue
        digest, size = _hash_file(file)
        if not digest:
            continue
        total_bytes += size
        all_hashes.append({"path": rel, "sha256": digest, "size_bytes": size})
        package_digest.update(rel.encode("utf-8"))
        package_digest.update(b"\0")
        package_digest.update(digest.encode("ascii"))
        package_digest.update(b"\0")
        suffix = file.suffix.lower()
        if suffix in BINARY_RISK_EXTS or suffix in PACKED_RISK_EXTS:
            risky_artifacts.append({
                "path": rel,
                "sha256": digest,
                "size_bytes": size,
                "kind": "native" if suffix in BINARY_RISK_EXTS else "packed",
            })

    inventory["package_hash"] = package_digest.hexdigest() if all_hashes else ""
    inventory["files_hashed"] = len(all_hashes)
    inventory["total_bytes_hashed"] = total_bytes
    inventory["risky_artifacts"] = risky_artifacts
    inventory["_all_file_hashes"] = all_hashes
    return inventory


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
    except OSError:
        return "", 0
    return digest.hexdigest(), size


def _known_bad_matches(
    artifact_inventory: dict[str, Any],
    known_bad_hashes: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not known_bad_hashes:
        return []
    matches: list[dict[str, Any]] = []
    package_hash = str(artifact_inventory.get("package_hash") or "").lower()
    if package_hash in known_bad_hashes:
        matches.append(_known_bad_match("package", package_hash, known_bad_hashes[package_hash]))

    for item in artifact_inventory.get("_all_file_hashes", []):
        if not isinstance(item, dict):
            continue
        digest = str(item.get("sha256") or "").lower()
        if digest not in known_bad_hashes:
            continue
        match = _known_bad_match(str(item.get("path") or ""), digest, known_bad_hashes[digest])
        match["size_bytes"] = item.get("size_bytes", 0)
        matches.append(match)
    return matches


def _known_bad_match(path: str, digest: str, metadata: dict[str, Any]) -> dict[str, Any]:
    match = dict(metadata)
    match.update({
        "path": path,
        "sha256": digest,
        "evidence_class": "confirmed",
    })
    return match


def _load_known_bad_hashes(path: Path | str | None = None) -> dict[str, dict[str, Any]]:
    raw_path = str(path or os.environ.get("IDE_SCANNER_KNOWN_BAD_HASHES_FILE") or "")
    if not raw_path:
        return {}
    try:
        text = Path(raw_path).read_text(encoding="utf-8")
    except OSError:
        return {}

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return _load_line_based_hashes(text, raw_path)
    return _load_json_hashes(parsed, raw_path)


def _load_json_hashes(parsed: Any, source_path: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if isinstance(parsed, dict):
        entries = parsed.get("hashes")
        if isinstance(entries, list):
            _collect_json_hash_entries(entries, out, source_path)
            return out
        for digest, metadata in parsed.items():
            if isinstance(digest, str) and SHA256_RE.fullmatch(digest.strip()):
                out[digest.lower()] = _hash_metadata(metadata, source_path)
    elif isinstance(parsed, list):
        _collect_json_hash_entries(parsed, out, source_path)
    return out


def _collect_json_hash_entries(entries: list[Any], out: dict[str, dict[str, Any]], source_path: str) -> None:
    for entry in entries:
        if isinstance(entry, str):
            digest = entry.strip().lower()
            if SHA256_RE.fullmatch(digest):
                out[digest] = {"source": source_path}
        elif isinstance(entry, dict):
            digest = str(entry.get("sha256") or entry.get("hash") or "").strip().lower()
            if SHA256_RE.fullmatch(digest):
                metadata = dict(entry)
                metadata.pop("sha256", None)
                metadata.pop("hash", None)
                out[digest] = _hash_metadata(metadata, source_path)


def _load_line_based_hashes(text: str, source_path: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        match = SHA256_RE.search(line)
        if match:
            out[match.group(0).lower()] = {"source": source_path}
    return out


def _hash_metadata(metadata: Any, source_path: str) -> dict[str, Any]:
    if isinstance(metadata, dict):
        out = dict(metadata)
    else:
        out = {"label": str(metadata)} if metadata else {}
    out.setdefault("source", source_path)
    return out


def _safe_extract_vsix(vsix_path: Path, destination: Path) -> dict[str, Any]:
    """Extract a VSIX with resource + traversal limits, returning anomalies.

    Members that would escape the destination (path traversal) or that carry a
    symlink mode are refused and recorded rather than silently dropped, so a
    crafted archive cannot make files disappear from the analyzed set while the
    scan still claims complete coverage. The returned dict is attached to the
    report so these anomalies surface as coverage limitations."""
    anomalies: dict[str, list[str]] = {"traversal_members": [], "symlink_members": [], "special_members": []}
    with zipfile.ZipFile(vsix_path) as archive:
        members = archive.infolist()
        files = [member for member in members if member.filename and not member.is_dir()]
        total_size = sum(member.file_size for member in files)
        compressed_size = sum(max(1, member.compress_size) for member in files)
        if len(files) > MAX_ARCHIVE_FILES:
            raise ValueError(f"VSIX contains too many files ({len(files)} > {MAX_ARCHIVE_FILES})")
        if total_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise ValueError("VSIX uncompressed size exceeds the extraction limit")
        if total_size / max(1, compressed_size) > MAX_ARCHIVE_COMPRESSION_RATIO:
            raise ValueError("VSIX compression ratio exceeds the extraction limit")
        extracted_bytes = 0
        for member in members:
            name = member.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            # Reject symlinks and other special (non-regular) members: a symlink
            # inside the archive could be dereferenced by later analysis to read
            # outside the extraction root.
            mode = (member.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                anomalies["symlink_members"].append(name)
                continue
            if mode and mode not in (0o100000, 0o040000):
                anomalies["special_members"].append(name)
                continue
            target = (destination / name).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                anomalies["traversal_members"].append(name)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as handle:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    extracted_bytes += len(chunk)
                    if extracted_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                        # The central-directory sizes are attacker-supplied; enforce
                        # the real byte cap during the write loop as well.
                        raise ValueError("VSIX extracted bytes exceeded the extraction limit")
                    handle.write(chunk)
    return {key: value for key, value in anomalies.items() if value}


def _record_archive_anomalies(report: "ExtensionReport", anomalies: dict[str, list[str]]) -> None:
    """Surface refused archive members as coverage limitations.

    A crafted VSIX can carry path-traversal, symlink, or special-file members
    that ``_safe_extract_vsix`` refuses to write to disk. Those members are real
    content that was NOT analyzed, so the scan must not keep claiming complete
    coverage. We record them on the inventory and downgrade coverage to
    ``incomplete`` so the fail-loud story reaches the report and UI."""
    if not anomalies:
        return
    report.artifact_inventory["archive_anomalies"] = {
        key: value[:50] for key, value in anomalies.items()
    }
    coverage = report.analysis_coverage
    limitations = list(coverage.get("limitations") or [])
    labels = {
        "traversal_members": "path-traversal",
        "symlink_members": "symlink",
        "special_members": "special-file",
    }
    for key, members in anomalies.items():
        if not members:
            continue
        label = labels.get(key, key)
        limitations.append(
            f"Refused {len(members)} {label} archive member(s) not analyzed: "
            + ", ".join(members[:3])
        )
    coverage["limitations"] = limitations
    coverage["status"] = "incomplete"
    report.artifact_inventory["scan_incomplete"] = True
    report.artifact_inventory["skipped_reason"] = "; ".join(limitations)


def _find_extracted_extension_root(root: Path) -> Path:
    preferred = root / "extension" / "package.json"
    if preferred.exists():
        return preferred.parent
    for package_json in root.rglob("package.json"):
        if "node_modules" in package_json.parts:
            continue
        return package_json.parent
    raise ValueError("VSIX did not contain an extension package.json")


def _apply_vsix_known_bad_match(report: ExtensionReport, known_bad_hashes: dict[str, dict[str, Any]]) -> None:
    vsix_hash = str(report.artifact_inventory.get("vsix_hash") or "").lower()
    if not vsix_hash or vsix_hash not in known_bad_hashes:
        return
    metadata = _known_bad_match("vsix", vsix_hash, known_bad_hashes[vsix_hash])
    finding = _finding(
        report.extension_id,
        report.version,
        "known-bad-artifact",
        "confirmed-intelligence",
        "CRITICAL",
        0.99,
        "VSIX hash matches a known-bad artifact entry.",
        [],
        "Block or remove this extension. The VSIX artifact hash matched confirmed malicious intelligence.",
        metadata,
    )
    report.findings.append(finding)
    report.artifact_inventory.setdefault("known_bad_matches", []).append(metadata)
    (
        report.verdict,
        report.verdict_reason,
        report.malware_authority,
        report.severity,
        report.malware_score,
        report.risk_score,
        report.score_details,
    ) = _classify_findings(report.findings)


def _walk_extension_files(path: Path) -> list[Path]:
    # Hash the complete packaged artifact. Static analysis applies its own
    # lower-noise filters, but artifact identity must include bundled output and
    # runtime dependencies because either can contain the code that executes.
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for filename in filenames:
            files.append(Path(dirpath, filename))
    return files


def _declared_entrypoints(manifest: dict[str, Any], path: Path) -> set[str]:
    entrypoints: set[str] = set()
    for key in ("main", "browser"):
        value = manifest.get(key)
        if isinstance(value, str) and value.strip():
            declared = _normalize_package_path(value)
            entrypoints.add(_resolve_node_entrypoint(path, declared))
    if not entrypoints and (path / "extension.js").is_file():
        entrypoints.add("extension.js")
    return entrypoints


def _normalize_package_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _resolve_node_entrypoint(root: Path, declared: str) -> str:
    """Resolve the file forms supported by Node for extension `main` fields."""
    candidates = [declared]
    if not Path(declared).suffix:
        candidates.extend(f"{declared}{suffix}" for suffix in (".js", ".cjs", ".mjs", ".json"))
        candidates.extend(f"{declared}/index{suffix}" for suffix in (".js", ".cjs", ".mjs", ".json"))
    for candidate in candidates:
        if root.joinpath(*candidate.split("/")).is_file():
            return candidate
    return declared


def _new_analysis_coverage(files: list[Path], entrypoints: set[str], path: Path) -> dict[str, Any]:
    all_paths = {file.relative_to(path).as_posix() for file in files}
    candidates = sorted(
        rel for rel in all_paths
        if Path(rel).suffix.lower() in EXEC_TEXT_EXTS and (rel in entrypoints or not _is_ignored_static_asset(rel))
    )
    # Executable-language files that exist in the artifact but were deliberately
    # excluded from the analyzed denominator because they are generated/vendored
    # bundles or minified blobs. They are reachable code, so they must be
    # reported as "skipped", never silently dropped from the coverage story.
    excluded_generated = sorted(
        rel for rel in all_paths
        if Path(rel).suffix.lower() in EXEC_TEXT_EXTS
        and rel not in entrypoints
        and _is_ignored_static_asset(rel)
    )
    return {
        "status": "pending",
        "coverage_percent": 0,
        "discovered_files": len(files),
        "declared_entrypoints": sorted(entrypoints),
        "resolved_entrypoints": sorted(entrypoints & all_paths),
        "missing_entrypoints": sorted(entrypoints - all_paths),
        "executable_candidates": candidates,
        "excluded_generated_files": excluded_generated,
        "analyzed_executable_files": [],
        "read_failures": [],
        "oversized_files": [],
        "limitations": [],
        "providers": {},
    }


def _finalize_analysis_coverage(coverage: dict[str, Any]) -> None:
    candidates = set(coverage.get("executable_candidates") or [])
    analyzed = set(coverage.get("analyzed_executable_files") or [])
    missing = list(coverage.get("missing_entrypoints") or [])
    failures = list(coverage.get("read_failures") or [])
    oversized = list(coverage.get("oversized_files") or [])
    limitations: list[str] = []
    manifest_validation = coverage.get("manifest_validation")
    if isinstance(manifest_validation, dict) and not manifest_validation.get("valid"):
        limitations.append(
            f"Manifest (package.json) is not trustworthy: {manifest_validation.get('status') or 'invalid'}"
        )
    if missing:
        limitations.append(f"Missing declared entrypoint(s): {', '.join(missing[:3])}")
    if failures:
        limitations.append(f"Could not read {len(failures)} executable file(s)")
    if oversized:
        limitations.append(f"Skipped {len(oversized)} executable file(s) larger than {MAX_TEXT_BYTES} bytes")
    required = candidates - set(oversized) - set(failures)
    if required - analyzed:
        limitations.append(f"Did not analyze {len(required - analyzed)} executable candidate(s)")
    providers = coverage.get("providers") if isinstance(coverage.get("providers"), dict) else {}
    required_providers = {
        item.strip().lower()
        for item in os.environ.get("IDE_SCANNER_REQUIRE_PROVIDERS", "").split(",")
        if item.strip()
    }
    required_providers.update(
        str(name).lower()
        for name, provider in providers.items()
        if isinstance(provider, dict) and provider.get("required") is True
    )
    for name in sorted(required_providers):
        provider = providers.get(name) if isinstance(providers.get(name), dict) else {}
        provider["required"] = True
        providers[name] = provider
        if provider.get("status") != "completed":
            limitations.append(f"Required provider {name} did not complete")
    excluded_generated = list(coverage.get("excluded_generated_files") or [])
    coverage["skipped_generated_count"] = len(excluded_generated)
    denominator = len(candidates) + len(missing)
    if denominator:
        coverage["coverage_percent"] = round(100 * len(analyzed & candidates) / denominator)
    elif excluded_generated:
        # No analyzable entrypoint or hand-written executable file was reachable,
        # yet the artifact ships generated/minified runtime code. Reporting 100%
        # here would claim full analysis of code that was never inspected.
        coverage["coverage_percent"] = 0
        limitations.append(
            f"No analyzable entrypoint was reachable; {len(excluded_generated)} generated/minified "
            "runtime file(s) were present but not analyzed"
        )
    else:
        coverage["coverage_percent"] = 100
    coverage["limitations"] = limitations
    coverage["status"] = "complete" if not limitations else "incomplete"


def _is_ignored_static_asset(rel: str) -> bool:
    normalized = rel.replace("\\", "/").lower()
    generated_prefixes = (
        "node_modules/",
        "assets/pdf.js/build/",
        "bundled/libs/debugpy/_vendored/",
        "drawio/src/main/webapp/math/es5/",
        "lib/build/pdf.js",
        "python_files/lib/",
        "sqlite-viewer-core/vscode/build/assets/",
        "vendor/",
        "vendors/",
        "webview/assets/",
        "webviews/build/assets/",
    )
    generated_parts = (
        "/build/static/js/",
        "/dist/",
        "/node_modules/",
    )
    if normalized.startswith(generated_prefixes) or any(part in normalized for part in generated_parts):
        return True
    name = Path(rel).name.lower()
    return name.endswith((
        ".chunk.js",
        ".chunk.mjs",
        ".min.js",
        ".min.mjs",
        ".bundle.js",
        ".bundle.mjs",
        ".map",
    ))


def _is_generated_code_blob(rel: str, text: str) -> bool:
    normalized = rel.replace("\\", "/").lower()
    if normalized.endswith((".min.js", ".min.mjs", ".bundle.js", ".bundle.mjs", ".chunk.js", ".chunk.mjs")):
        return True
    newline_count = text.count("\n")
    if len(text) >= GENERATED_BLOB_BYTES:
        return True
    if len(text) >= MINIFIED_BLOB_BYTES and newline_count < 20:
        return True
    if len(text) >= MINIFIED_BLOB_BYTES and len(text) / max(1, newline_count + 1) > 500:
        return True
    return False


def _read_manifest_status(path: Path) -> tuple[dict[str, Any], str]:
    """Read a package.json manifest and report validity.

    Returns ``(manifest, status)`` where status is ``valid`` (parsed object
    carrying trustworthy identity), ``missing`` (no file), ``unreadable``
    (OS/permission error), ``invalid-json`` (present but not parseable),
    ``not-object`` (parsed to a non-object), or ``missing-identity`` (parsed
    object without the non-empty string ``publisher``/``name``/``version``
    fields every real VS Code extension declares). A non-``valid`` status must
    fail the scan closed: an artifact whose identity manifest cannot be trusted
    may not be reported ``allow`` or ``complete``. Fabricating an identity from
    the folder name (``unknown.<dir>@0.0.0``) and then reporting ``allow`` would
    let an artifact with no verifiable identity pass silently."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}, "missing"
    except OSError:
        return {}, "unreadable"
    try:
        parsed = loads_jsonc(raw)
    except Exception:
        return {}, "invalid-json"
    if not isinstance(parsed, dict):
        return {}, "not-object"
    if not _has_manifest_identity(parsed):
        return parsed, "missing-identity"
    return parsed, "valid"


def _has_manifest_identity(manifest: dict[str, Any]) -> bool:
    """True only when the manifest declares the identity fields a genuine VS
    Code extension always carries: non-empty string ``publisher``, ``name``,
    and ``version``. An empty or partial object cannot establish a trustworthy
    artifact identity and must not be treated as a valid manifest."""
    for field in ("publisher", "name", "version"):
        value = manifest.get(field)
        if not isinstance(value, str) or not value.strip():
            return False
    return True


def _read_manifest(path: Path) -> dict[str, Any]:
    manifest, _status = _read_manifest_status(path)
    return manifest


def _javascript_ast_provider_status(statuses: list[str], failed_paths: list[str] | None = None) -> dict[str, Any]:
    """Summarize per-file JS/TS AST walker statuses into a provider record.

    ``completed`` only when every analyzed file's walker ran successfully. A
    missing Node runtime, timeout, spawn error, or malformed walker output on
    any file marks the provider ``failed`` (required), so coverage finalization
    records a limitation and the scan cannot report ``complete``/``allow`` on
    the strength of AST analysis that never actually ran.

    ``unparsed`` files (TypeScript/JSX or syntactically invalid source that the
    plain-JS vendored parser cannot read) are a disclosed tool limitation, not
    an analyzer failure: the raw-text rule layer still scans them, so they are
    counted and reported but do not flip the provider to ``failed``. Reporting
    them as a silent ``completed`` would falsely claim AST coverage the scanner
    never had.

    Fail-closed invariant, honest scope: an unparsed *non-entrypoint* file does
    not by itself block ``allow`` -- raw-text coverage is deemed sufficient for
    incidental files. An unparsed *declared entrypoint* is different: the
    primary activation code path lost structural evasion detection, so
    ``scan_extension`` emits an ``entrypoint-ast-unparsed`` posture finding that
    forces the decision to at least ``review``. This provider record stays
    ``completed`` in both cases; the review gate lives in the finding, not
    here."""
    record: dict[str, Any] = {
        "provider": "javascript_ast",
        "required": True,
        "timeout_seconds_per_file": JS_AST_TIMEOUT_SECONDS,
        "max_timeout_attempts": JS_AST_TIMEOUT_ATTEMPTS,
        "max_old_space_mb": JS_AST_MAX_OLD_SPACE_MB,
    }
    if not statuses:
        # No JS/TS files were reachable; nothing for this provider to do.
        record["status"] = "completed"
        record["analyzed_files"] = 0
        return record
    hard_failures = [s for s in statuses if s not in ("ok", "unparsed")]
    unparsed = [s for s in statuses if s == "unparsed"]
    record["analyzed_files"] = len(statuses)
    record["failed_files"] = len(hard_failures)
    if unparsed:
        record["unparsed_files"] = len(unparsed)
    if hard_failures:
        reasons = sorted(set(hard_failures))
        record["status"] = "failed"
        record["error"] = f"AST analysis did not complete for {len(hard_failures)} file(s): {', '.join(reasons)}"
        if failed_paths:
            record["failed_paths"] = sorted(set(failed_paths))
        if "node-missing" in reasons:
            record["error"] = "Node runtime unavailable; JavaScript AST analysis did not run."
    elif unparsed:
        record["status"] = "completed"
        record["note"] = (
            f"AST analysis skipped {len(unparsed)} file(s) the plain-JS parser "
            "could not read (TypeScript/JSX or invalid syntax); raw-text rules "
            "still applied."
        )
    else:
        record["status"] = "completed"
    return record


def _read_text(path: Path) -> str | None:
    """Read up to MAX_TEXT_BYTES from a file without loading the whole file.

    A hostile artifact can ship a multi-gigabyte "source" file; reading it
    fully into memory before slicing would let a single file exhaust RAM. We
    read a bounded prefix in one bounded call so peak memory is capped at the
    limit regardless of the file's real size."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_TEXT_BYTES)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


# AST rules that are noise on minified/generated bundles because the pattern is
# structurally ubiquitous there. Retained on hand-written code.
_GENERATED_NOISE_AST_RULES = {"ast-dynamic-call-target", "ast-bracket-notation-sensitive-access"}


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that share a finding_id (identical rule + file_refs +
    evidence summary) to the first occurrence, preserving order. Multiple
    analyzers and code paths can surface the same fact; the report should state
    it once. Scoring is unaffected -- component scores use max(), not counts."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.finding_id in seen:
            continue
        seen.add(finding.finding_id)
        unique.append(finding)
    return unique


def _add_ast_findings(
    extension_id: str,
    version: str,
    rel: str,
    text: str,
    findings: list[Finding],
    generated: bool = False,
) -> str:
    """Append AST findings and return the walker status for this file.

    Status is one of ``ok``/``unparsed``/``node-missing``/``timeout``/``error``/
    ``malformed`` (see ``analyze_js_source_status``). The caller aggregates these
    into a truthful ``javascript_ast`` provider record so a missing Node runtime
    or a parse failure on a real entrypoint is never silently reported as
    complete."""
    items, status = analyze_js_source_status(rel, text)
    for item in items:
        rule_id = str(item.get("rule") or "")
        if not rule_id:
            continue
        # Minified/bundled output makes computed member access (obj[x]()) and
        # bracket-notation property access ubiquitous and structurally
        # meaningless -- every property is emitted this way. Suppressing these
        # two rules on generated blobs removes hundreds of zero-signal findings
        # per bundle. `ast-constructed-dynamic-argument` (call target built via
        # string-concat/fromCharCode) is a genuine obfuscation signal even in
        # minified code, so it is retained.
        if generated and rule_id in _GENERATED_NOISE_AST_RULES:
            continue
        severity = str(item.get("severity") or "MEDIUM")
        if severity not in _SEVERITY_TO_CONFIDENCE:
            severity = "MEDIUM"
        line = item.get("line")
        detail = str(item.get("detail") or "Dynamic construction detected by AST analysis.")
        summary = f"{detail} (line {line})" if isinstance(line, int) else detail
        findings.append(_finding(
            extension_id,
            version,
            rule_id,
            "code",
            severity,
            _SEVERITY_TO_CONFIDENCE[severity],
            summary,
            [rel],
            "Confirm whether the dynamically constructed target/argument is attacker-influenceable; this evades plain-text regex detection by design.",
            evidence={"line": line} if isinstance(line, int) else None,
        ))
    return status


_SEVERITY_TO_CONFIDENCE = {"HIGH": 0.8, "MEDIUM": 0.65, "LOW": 0.5}


def _finding(
    extension_id: str,
    version: str,
    rule_id: str,
    category: str,
    severity: str,
    confidence: float,
    evidence_summary: str,
    file_refs: list[str],
    recommendation: str,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    payload = f"{extension_id}:{version}:{rule_id}:{','.join(file_refs)}:{evidence_summary}"
    return Finding(
        finding_id=_stable_id(payload),
        extension_id=extension_id,
        version=version,
        rule_id=rule_id,
        category=category,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,
        score=score_finding(severity, confidence),
        evidence_type="static",
        evidence_summary=evidence_summary,
        file_refs=file_refs,
        recommendation=recommendation,
        evidence=_evidence_with_class(rule_id, evidence),
    )


def _evidence_with_class(rule_id: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    data = dict(evidence or {})
    data.setdefault("evidence_class", _evidence_class(rule_id, data))
    return data


def _evidence_class(rule_id: str, evidence: dict[str, Any] | None = None) -> str:
    if rule_id in CONFIRMED_RULES:
        return "confirmed"
    if rule_id == "marketplace-removed-package":
        return "confirmed" if _is_removed_malware(evidence) else "provenance"
    if rule_id in CORRELATED_RULES:
        return "correlated"
    if rule_id in EXPOSURE_RULES:
        return "exposure"
    if rule_id in CAPABILITY_RULES:
        return "capability"
    if rule_id in DEPENDENCY_RULES:
        return "dependency"
    if rule_id in PROVENANCE_RULES:
        return "provenance"
    if rule_id in POSTURE_RULES:
        return "posture"
    if rule_id in OBSERVED_RULES or rule_id == "observed-secret-read" or rule_id == "observed-unexpected-network":
        return "observed"
    if rule_id in REPUTATION_RULES:
        return "reputation"
    if rule_id.startswith("secret-reference:"):
        return "weak"
    return "weak"


def _classify_findings(findings: list[Finding]) -> tuple[str, str, str, str, int, int, dict[str, Any]]:
    score_details = _score_details(findings)
    if not findings:
        return "clean", "No suspicious extension behavior was detected by local static analysis.", "none", "INFO", 0, 0, score_details

    severity = "INFO"
    decision_relevant = [finding for finding in findings if is_decision_relevant(finding)]
    for finding in decision_relevant:
        severity = rank_severity(severity, effective_finding_severity(finding))
    malware_score = int(score_details["malware_score"])
    risk_score = int(score_details["risk_score"])

    confirmed = [finding for finding in findings if _is_confirmed_malware_finding(finding)]
    if confirmed:
        return (
            "malicious",
            "Confirmed registry or malicious-package evidence matched this extension.",
            "authoritative",
            severity,
            malware_score,
            risk_score,
            score_details,
        )

    high_correlated = [
        finding for finding in findings
        if _finding_evidence_class(finding) == "correlated" and finding.severity in {"HIGH", "CRITICAL"}
    ]
    if high_correlated:
        return (
            "suspicious",
            "Correlated static evidence matches a realistic abuse path and needs manual verification.",
            "non_authoritative",
            severity,
            malware_score,
            risk_score,
            score_details,
        )

    suspicious_removed = [finding for finding in findings if _is_suspicious_removed_finding(finding)]
    if suspicious_removed:
        return (
            "suspicious",
            "Marketplace removal evidence says this extension was removed as suspicious.",
            "non_authoritative",
            severity,
            malware_score,
            risk_score,
            score_details,
        )

    high_observed = [
        finding for finding in findings
        if _finding_evidence_class(finding) == "observed" and finding.severity in {"HIGH", "CRITICAL"}
    ]
    if high_observed:
        return (
            "suspicious",
            "Sandbox observation evidence matched a realistic abuse path and needs manual verification.",
            "non_authoritative",
            severity,
            malware_score,
            risk_score,
            score_details,
        )

    has_actionable_review = any(is_review_relevant(finding) for finding in findings)
    if has_actionable_review:
        return (
            "review",
            "The extension exposes sensitive capabilities or non-confirmed risk evidence that needs context.",
            "none",
            severity,
            malware_score,
            risk_score,
            score_details,
        )

    if decision_relevant:
        low_details = _low_note_score_details(score_details)
        return (
            "clean",
            "Analysis found low-severity hardening notes but no evidence requiring approval review.",
            "none",
            severity,
            0,
            int(low_details["risk_score"]),
            low_details,
        )

    return (
        "clean",
        "No actionable malware, abuse-chain, dependency, provenance, or sensitive-capability evidence was identified.",
        "none",
        "INFO",
        0,
        0,
        _non_actionable_score_details(score_details),
    )


def _is_actionable_review_finding(finding: Finding) -> bool:
    return is_review_relevant(finding)


def _low_note_score_details(score_details: dict[str, Any]) -> dict[str, Any]:
    details = dict(score_details)
    risk_score = min(32, max(1, int(details.get("risk_score") or 0)))
    details["score"] = risk_score
    details["malware_score"] = 0
    details["risk_score"] = risk_score
    details["basis"] = "low_hardening"
    details["confidence"] = "medium"
    return details


def _non_actionable_score_details(score_details: dict[str, Any]) -> dict[str, Any]:
    details = dict(score_details)
    details["score"] = 0
    details["malware_score"] = 0
    details["risk_score"] = 0
    details["basis"] = "none"
    details["confidence"] = "high"
    return details


def _empty_score_details() -> dict[str, Any]:
    return {
        "score": 0,
        "malware_score": 0,
        "risk_score": 0,
        "confidence": "high",
        "basis": "none",
        "components": {
            "confirmed_intelligence": 0,
            "observed_behavior": 0,
            "correlated_behavior": 0,
            "sensitive_capability": 0,
            "provenance": 0,
            "dependency": 0,
            "vulnerability": 0,
            "posture": 0,
            "cross_extension_exposure": 0,
            "reputation": 0,
            "weak_context": 0,
        },
        "suppressors": [],
        "counts": {
            "confirmed": 0,
            "observed": 0,
            "correlated": 0,
            "capability": 0,
            "provenance": 0,
            "dependency": 0,
            "vulnerability": 0,
            "posture": 0,
            "exposure": 0,
            "reputation": 0,
            "weak": 0,
        },
    }


def _score_details(findings: list[Finding]) -> dict[str, Any]:
    details = _empty_score_details()
    counts = details["counts"]
    for finding in findings:
        evidence_class = _finding_evidence_class(finding)
        counts[evidence_class] = counts.get(evidence_class, 0) + 1

    confirmed_score = _confirmed_score(findings)
    correlated_score = _correlated_score(findings)
    capability_score = _capability_score(findings)
    provenance_score = _provenance_score(findings)
    dependency_score = _dependency_score(findings)
    vulnerability_score = _vulnerability_score(findings)
    observed_score = _observed_score(findings)
    posture_score = _posture_score(findings)
    exposure_score = _exposure_score(findings)
    reputation_score = _reputation_score(findings)
    has_actionable_context = (
        correlated_score > 0
        or capability_score > 0
        or provenance_score > 0
        or dependency_score > 0
        or vulnerability_score > 0
        or observed_score > 0
        or posture_score > 0
        or exposure_score > 0
    )
    weak_score = _weak_score(findings, has_actionable_context)

    components = {
        "confirmed_intelligence": confirmed_score,
        "observed_behavior": observed_score,
        "correlated_behavior": correlated_score,
        "sensitive_capability": capability_score,
        "provenance": provenance_score,
        "dependency": dependency_score,
        "vulnerability": vulnerability_score,
        "posture": posture_score,
        "cross_extension_exposure": exposure_score,
        "reputation": reputation_score,
        "weak_context": weak_score,
    }
    # Schema v2 reserves the malware index for authoritative intelligence and
    # high-specificity runtime proof. Static correlations remain visible in the
    # investigation-priority score, but no longer masquerade as malware proof.
    malware_score = max(confirmed_score, _proven_observed_score(findings))

    risk_components = {
        name: score for name, score in components.items()
        if name != "reputation" or has_actionable_context
    }
    risk_score = max(risk_components.values())
    if risk_score < 100 and has_actionable_context:
        risk_score = min(99, risk_score + min(10, weak_score) + min(5, reputation_score))
        risk_score = max(0, risk_score - _suppressor_reduction(findings))

    basis, confidence = _score_basis(components)

    details["score"] = risk_score
    details["malware_score"] = malware_score
    details["risk_score"] = risk_score
    details["confidence"] = confidence
    details["basis"] = basis
    details["components"] = components
    details["suppressors"] = _suppressors(findings)
    return details


def _score_basis(components: dict[str, int]) -> tuple[str, str]:
    priority = [
        "confirmed_intelligence",
        "observed_behavior",
        "correlated_behavior",
        "vulnerability",
        "dependency",
        "provenance",
        "sensitive_capability",
        "cross_extension_exposure",
        "posture",
        "reputation",
        "weak_context",
    ]
    basis = max(priority, key=lambda name: (components.get(name, 0), -priority.index(name)))
    if components.get(basis, 0) == 0:
        return "none", "high"
    confidence = "high" if basis == "confirmed_intelligence" else "low" if basis in {"posture", "reputation", "weak_context"} else "medium"
    return basis, confidence


def _confirmed_score(findings: list[Finding]) -> int:
    if any(finding.rule_id == "known-bad-artifact" for finding in findings):
        return 100
    if any(finding.rule_id == "marketplace-removed-malware" for finding in findings):
        return 100
    if any(finding.rule_id == "marketplace-removed-package" and _is_removed_malware(finding.evidence) for finding in findings):
        return 100
    if any(finding.rule_id == "malicious-npm-dependency" for finding in findings):
        return 98
    if any(finding.rule_id == "trusted-threat-feed-hit" for finding in findings):
        return 100
    return 0


def _correlated_score(findings: list[Finding]) -> int:
    # A rule ID can be deliberately reclassified as a capability when product
    # controls reduce it from an abuse-path finding. Only findings that remain
    # correlated evidence may drive this score component.
    rule_ids = {
        finding.rule_id
        for finding in findings
        if _finding_evidence_class(finding) == "correlated"
    }
    score = 0
    if "install-secret-access" in rule_ids:
        score = max(score, 86)
    if "install-shell-obfuscation" in rule_ids:
        score = max(score, 84)
    if "install-download-execute" in rule_ids:
        score = max(score, 82)
    if "credential-exfiltration-chain" in rule_ids:
        score = max(score, 87)
    if "destructive-transfer-chain" in rule_ids:
        score = max(score, 83)
    if "obfuscation-execution-network" in rule_ids:
        score = max(score, 80)
    if "persistence-chain" in rule_ids:
        score = max(score, 82)
    if "agent-data-exfil-chain" in rule_ids:
        score = max(score, 84)
    if "supply-chain-dropper-chain" in rule_ids:
        score = max(score, 76)
    if "download-and-execute" in rule_ids:
        score = max(score, 72)
    if "credential-dataflow-to-network" in rule_ids:
        score = max(score, 88)
    if "credential-dataflow-to-process" in rule_ids:
        score = max(score, 78)
    if "credential-dataflow-to-file" in rule_ids:
        score = max(score, 76)
    if "credential-command-control" in rule_ids:
        score = max(score, 74)
    if "clipboard-read-near-secret-input" in rule_ids:
        score = max(score, 72)
    if "untrusted-workspace-input-to-process" in rule_ids:
        score = max(score, 82)
    if "webview-message-to-process" in rule_ids:
        score = max(score, 84)
    if any(
        finding.rule_id in {"decoded-payload-execution", "encoded-dynamic-execution"}
        and _finding_evidence_class(finding) == "correlated"
        for finding in findings
    ):
        score = max(score, 82)
    return score


def _capability_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if finding.rule_id in {"agent-shell-tool", "agent-filesystem-tool", "agent-network-tool"}:
            score = max(score, 48)
        elif finding.rule_id == "mcp-server-command":
            score = max(score, 44)
        elif finding.rule_id == "agent-prompt-injection-sink":
            score = max(score, 42)
        elif finding.rule_id == "agentic-tooling":
            score = max(score, 41)
        elif finding.rule_id == "lifecycle-script":
            score = max(score, 38)
        elif finding.rule_id == "native-or-packed-artifact":
            score = max(score, 36)
        elif finding.rule_id == "dynamic-shell-execution":
            score = max(score, 40)
        elif finding.rule_id in {"untrusted-input-execution", "untrusted-workspace-input-to-process"}:
            score = max(score, 38)
        elif finding.rule_id in {"broad-activation", "sensitive-activation", "powerful-ide-contribution"}:
            score = max(score, 30)
        elif finding.rule_id == "webview-csp-unsafe-directive":
            score = max(score, 34)
        elif finding.rule_id == "webview-csp-missing":
            score = max(score, 28)
        elif finding.rule_id == "startup-activation":
            score = max(score, 20)
    return score


def _provenance_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if finding.rule_id == "marketplace-removed-package":
            removal_type = _removal_type(finding.evidence)
            if removal_type in SUSPICIOUS_REMOVAL_TYPES:
                score = max(score, 88)
            elif removal_type:
                score = max(score, 82)
        elif _finding_evidence_class(finding) == "provenance":
            score = max(score, finding.score)
    return score


def _dependency_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if finding.category != "dependency":
            continue
        if finding.rule_id == "malicious-npm-dependency":
            score = max(score, 98)
        elif finding.rule_id == "vulnerable-npm-dependency":
            exact = bool((finding.evidence or {}).get("exact"))
            if exact:
                score = max(score, 65)
        elif finding.rule_id == "mutable-dependency-source":
            score = max(score, 46)
        elif finding.rule_id == "unpinned-dependency":
            score = max(score, 28)
    return score


def _vulnerability_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if _finding_evidence_class(finding) == "vulnerability":
            score = max(score, finding.score)
    return score


def _observed_score(findings: list[Finding]) -> int:
    rule_ids = {finding.rule_id for finding in findings}
    score = 0
    if "observed-secret-exfil" in rule_ids:
        score = max(score, 89)
    if "observed-destructive-behavior" in rule_ids:
        score = max(score, 88)
    if "observed-download-execute" in rule_ids:
        score = max(score, 84)
    if "observed-persistence" in rule_ids:
        score = max(score, 82)
    if "observed-secret-read" in rule_ids:
        score = max(score, 52)
    if "observed-unexpected-network" in rule_ids:
        score = max(score, 38)
    if "observed-process-exec" in rule_ids:
        score = max(score, 36)
    if "observed-filesystem-write" in rule_ids:
        score = max(score, 22)
    return score


def _proven_observed_score(findings: list[Finding]) -> int:
    rule_ids = {finding.rule_id for finding in findings}
    if "observed-secret-exfil" in rule_ids:
        return 89
    if "observed-destructive-behavior" in rule_ids:
        return 88
    if "observed-download-execute" in rule_ids:
        return 84
    if "observed-persistence" in rule_ids:
        return 82
    return 0


def _posture_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if finding.rule_id == "dangerous-github-workflow":
            score = max(score, 44)
        elif finding.rule_id == "workflow-token-permissions-broad":
            score = max(score, 34)
        elif finding.rule_id == "repo-binary-artifacts":
            score = max(score, 32)
    return score


def _exposure_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if finding.rule_id == "credential-dataflow-to-network":
            score = max(score, 92)
        elif finding.rule_id == "credential-source-near-network":
            score = max(score, 54)
        elif finding.rule_id in {"credential-source-near-process", "credential-source-near-file"}:
            score = max(score, 48)
        elif finding.rule_id == "agent-sensitive-data-near-network":
            score = max(score, 46)
        elif finding.rule_id in {"credential-input-near-state", "clipboard-near-credential-surface"}:
            score = max(score, 52)
        elif finding.rule_id == "unrestricted-workspace-cli-path":
            score = max(score, 72)
        elif finding.rule_id in {"credential-command-control", "clipboard-read-near-secret-input"}:
            score = max(score, 72)
        elif finding.rule_id in {"credential-dataflow-to-process", "credential-dataflow-to-file"}:
            score = max(score, 68)
        elif finding.rule_id in {"credential-config-update", "credential-global-state-storage"}:
            score = max(score, 58)
        elif finding.rule_id == "credential-inputbox-prompt":
            score = max(score, 42)
        elif finding.rule_id == "credential-command-execution":
            score = max(score, 40)
        elif finding.rule_id in {"credential-config-key", "credential-global-state-key", "credential-command-registration"}:
            score = max(score, 24)
    return score


def _reputation_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if _finding_evidence_class(finding) != "reputation":
            continue
        if finding.rule_id == "marketplace-extension-not-found":
            score = max(score, 12)
        elif finding.rule_id == "marketplace-unverified-publisher":
            score = max(score, 8)
        elif finding.rule_id == "marketplace-low-install-count":
            score = max(score, 8)
        elif finding.rule_id == "marketplace-low-rating":
            score = max(score, 10)
        elif finding.rule_id == "marketplace-stale-extension":
            score = max(score, 8)
        elif finding.rule_id == "install-rating-mismatch":
            score = max(score, 10)
        elif finding.rule_id in {"repo-archived", "repo-stale"}:
            score = max(score, 8)
        elif finding.rule_id in {"repo-url-missing", "security-policy-missing", "license-missing"}:
            score = max(score, 6)
    return score


def _suppressors(findings: list[Finding]) -> list[dict[str, Any]]:
    suppressors: list[dict[str, Any]] = []
    if any(finding.rule_id == "marketplace-verified-publisher" for finding in findings):
        suppressors.append({
            "id": "verified-publisher",
            "reduction": 5,
            "reason": "Marketplace metadata reports a verified publisher. This reduces reputation risk only.",
        })
    return suppressors


def _suppressor_reduction(findings: list[Finding]) -> int:
    # Publisher verification is reputation context, not a reason to discount
    # observed code behavior, capabilities, dependencies, or provenance.
    return 0


def _weak_score(findings: list[Finding], has_actionable_context: bool) -> int:
    weak_count = sum(1 for finding in findings if _finding_evidence_class(finding) == "weak")
    if weak_count == 0 or not has_actionable_context:
        return 0
    return min(15, weak_count * 2)


def _finding_evidence_class(finding: Finding) -> str:
    evidence_class = (finding.evidence or {}).get("evidence_class")
    if isinstance(evidence_class, str):
        return evidence_class
    return _evidence_class(finding.rule_id, finding.evidence)


def _is_confirmed_malware_finding(finding: Finding) -> bool:
    if finding.rule_id == "known-bad-artifact":
        return True
    if finding.rule_id == "malicious-npm-dependency":
        return True
    if finding.rule_id == "trusted-threat-feed-hit":
        return True
    if finding.rule_id == "marketplace-removed-malware":
        return True
    return finding.rule_id == "marketplace-removed-package" and _is_removed_malware(finding.evidence)


def _is_suspicious_removed_finding(finding: Finding) -> bool:
    return finding.rule_id == "marketplace-removed-package" and _removal_type(finding.evidence) in SUSPICIOUS_REMOVAL_TYPES


def _is_removed_malware(evidence: dict[str, Any] | None) -> bool:
    return _removal_type(evidence) in MALWARE_REMOVAL_TYPES


def _removal_type(evidence: dict[str, Any] | None) -> str:
    if not evidence:
        return ""
    return str(evidence.get("type") or evidence.get("removal_type") or "").strip().lower()


def _stable_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _manifest_hash(path: Path) -> str:
    digest = hashlib.sha256()
    for file in sorted(path.glob("package*.json")):
        try:
            digest.update(file.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()[:24]


def _repository_url(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("url") or "")
    return ""


def _dependencies(manifest: dict[str, Any], path: Path) -> dict[str, str]:
    locked = _package_lock_dependencies(path / "package-lock.json")
    if locked:
        return locked

    out = _manifest_runtime_dependencies(manifest)
    for name in list(out):
        installed_version = _installed_package_version(path, name)
        if installed_version:
            out[name] = installed_version
    return out


def _manifest_runtime_dependencies(manifest: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    deps = manifest.get("dependencies")
    if not isinstance(deps, dict):
        return out
    for name, version in deps.items():
        if isinstance(name, str) and isinstance(version, str):
            out[name] = version
    return out


def _dependency_inventory(manifest: dict[str, Any], dependencies: dict[str, str]) -> list[dict[str, Any]]:
    direct = set(_manifest_runtime_dependencies(manifest))
    return [
        {
            "name": name,
            "version": version,
            "relationship": "direct" if name in direct else "transitive",
            "ecosystem": "npm",
        }
        for name, version in sorted(dependencies.items())
    ]


def _package_lock_dependencies(path: Path) -> dict[str, str]:
    try:
        data = loads_jsonc(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}

    packages = data.get("packages")
    if isinstance(packages, dict):
        return _package_lock_v2_dependencies(packages)

    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        out: dict[str, str] = {}
        _collect_package_lock_v1_dependencies(dependencies, out)
        return out
    return {}


def _package_lock_v2_dependencies(packages: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for package_path, package_data in packages.items():
        if not isinstance(package_path, str) or not package_path.startswith("node_modules/"):
            continue
        if not isinstance(package_data, dict) or package_data.get("dev") is True:
            continue
        version = package_data.get("version")
        if not isinstance(version, str):
            continue
        name = _package_name_from_node_modules_path(package_path)
        if name:
            out[name] = version
    return out


def _collect_package_lock_v1_dependencies(dependencies: dict[str, Any], out: dict[str, str]) -> None:
    for name, package_data in dependencies.items():
        if not isinstance(name, str) or not isinstance(package_data, dict):
            continue
        if package_data.get("dev") is True:
            continue
        version = package_data.get("version")
        if isinstance(version, str):
            out[name] = version
        child_dependencies = package_data.get("dependencies")
        if isinstance(child_dependencies, dict):
            _collect_package_lock_v1_dependencies(child_dependencies, out)


def _package_name_from_node_modules_path(package_path: str) -> str:
    parts = package_path.split("/")
    try:
        index = parts.index("node_modules")
    except ValueError:
        return ""
    package_parts = parts[index + 1:]
    if not package_parts:
        return ""
    if package_parts[0].startswith("@"):
        if len(package_parts) < 2:
            return ""
        return f"{package_parts[0]}/{package_parts[1]}"
    return package_parts[0]


def _installed_package_version(root: Path, name: str) -> str:
    package_path = root / "node_modules" / Path(*name.split("/")) / "package.json"
    manifest = _read_manifest(package_path)
    version = manifest.get("version")
    return version if isinstance(version, str) else ""


def _is_mutable_dependency_spec(spec: str) -> bool:
    if spec.startswith(("git://", "git+", "github:", "http://", "https://", "file:", "link:", "workspace:")):
        return True
    if ".git" in spec:
        return True
    return bool(re.match(r"^[^@\s]+/[^@\s]+(?:#.+)?$", spec))
