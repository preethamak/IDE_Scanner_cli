from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from concurrent.futures import ProcessPoolExecutor
from itertools import repeat
from pathlib import Path
from typing import Any

from .artifact_store import ArtifactStore, ArtifactStoreError, StoredArtifact, artifact_store_from_environment
from .artifact_input import ArtifactInputError, acquire_https_vsix
from .build_identity import scanner_build

from .ast_analyzer import (
    JS_AST_EXTS,
    JS_AST_MAX_INPUT_BYTES,
    JS_AST_MAX_OLD_SPACE_MB,
    JS_AST_TIMEOUT_ATTEMPTS,
    JS_AST_TIMEOUT_SECONDS,
    analyze_js_source_status,
    node_available,
)
from .bundle_analysis import analyze_generated_bundle
from .calibration import calibrated_score, max_calibrated_score
from .capability_contracts import class_contract, classify_extension, expected_capabilities
from .classification_policy import (
    POLICY_VERSION,
    effective_finding_severity,
    finding_actionability,
    is_decision_relevant,
    is_review_relevant,
)
from .contracts import ScanRequest
from .discovery import discover_from_path, discover_local_installations
from .jsonc import loads_jsonc
from .models import ExtensionReport, Finding
from .module_flow import (
    MAX_FLOW_DEPTH,
    MAX_FLOW_MODULES,
    MAX_FLOW_PATHS,
    FlowAnalysisLimitError,
    credential_exfiltration_flow,
    has_integrity_gate,
    module_flow_coverage,
    module_summary,
    remote_vsix_install_flow,
)
from .value_flow import credential_value_flow
from .public_outcomes import apply_public_assessment
from .rule_registry import RULESET_VERSION
from .posture import scan_posture, summarize_posture
from .providers import run_static_providers
from .providers.runtime import SEMGREP_MAX_TARGET_BYTES, run_bounded_process, safe_child_environment
from .sandbox_runner import external_trace_available, run_sandbox
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
DOCUMENTATION_PREVIEW_EXTS = {".md", ".markdown", ".rst"}
BINARY_RISK_EXTS = {".dll", ".dylib", ".exe", ".node", ".so"}
PACKED_RISK_EXTS = {".7z", ".asar", ".gz", ".jar", ".rar", ".tar", ".tgz", ".war", ".zip"}
WASM_LOADER_RE = re.compile(
    r"\bWebAssembly\.(?:instantiate|instantiateStreaming|compile|compileStreaming|Module)\b"
    r"|(?:readFile(?:Sync)?|fetch|request|arrayBuffer)\s*\([^\n]{0,500}\.wasm\b",
    re.I,
)
DEEP_REQUIRED_PROVIDERS = frozenset({"semgrep", "yara", "dependency_intelligence"})
ARTIFACT_ORIGINS = frozenset({"user_uploaded_vsix", "installed_directory", "local_directory", "archive_artifact", "source_snapshot"})
SKIP_DIRS = {".git", ".hg", ".svn"}
MAX_TEXT_BYTES = 64 * 1024 * 1024
# A local extension can contain generated language-server/runtime payloads that
# are valid artifacts but are not a safe unit for an all-local inventory scan.
# Enforce a hard budget before hashing, Semgrep, or AST work. Exceeding it is
# an explicit incomplete result (never an allow/clean result), so publication
# gates can quarantine the artifact instead of risking a false negative or a
# worker that never finishes.
MAX_EXTENSION_FILES = 50_000
MAX_EXTENSION_BYTES = 512 * 1024 * 1024
MAX_SOURCE_PREVIEW_BYTES = 200 * 1024
MAX_SOURCE_PREVIEWS = 40
# Multi-megabyte entrypoints are treated as generated for correlation and AST
# budgeting even when pretty-printed. This keeps one vendor bundle from making
# an inventory scan unbounded while raw-text and YARA coverage remain active.
GENERATED_BLOB_BYTES = 10 * 1024 * 1024
GENERATED_ENTRYPOINT_AST_MAX_BYTES = JS_AST_MAX_INPUT_BYTES
# Generated webpack/esbuild output can be substantially smaller than 1 MiB.
# Treat a long, nearly line-free JavaScript artifact as generated once it is
# large enough that character proximity no longer represents source locality.
MINIFIED_BLOB_BYTES = 256 * 1024
SEMGREP_MINIFIED_SOURCE_BYTES = 16 * 1024
MAX_ARCHIVE_FILES = 100_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_COMPRESSION_RATIO = 100
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CONFIRMED_RULES = {
    "known-bad-artifact",
    "known-malicious-extension",
    "marketplace-removed-malware",
    "malicious-npm-dependency",
    "trusted-threat-feed-hit",
}
OBSERVED_RULES = {
    "observed-secret-exfil",
    "observed-download-execute",
    "observed-persistence",
    "observed-destructive-behavior",
    "observed-process-exec",
    "observed-filesystem-write",
    "observed-unexpected-capability",
}
CORRELATED_RULES = {
    "agent-data-exfil-chain",
    "credential-exfiltration-chain",
    "credential-harvesting-exfiltration",
    "credential-identifier-flow-to-network",
    "environment-data-exfiltration",
    "destructive-transfer-chain",
    "download-and-execute",
    "install-download-execute",
    "install-secret-access",
    "install-shell-obfuscation",
    "obfuscation-execution-network",
    "persistence-chain",
    "remote-vsix-install-chain",
    "hidden-remote-workspace-task",
    "obfuscated-credential-harvesting-exfiltration",
    "supply-chain-dropper-chain",
}
# A remote extension update without visible integrity verification is a serious
# supply-chain review signal, but legitimate extension managers use this shape.
# Destructive archive/upload workflows and local command servers are also common
# in backup, deployment, and IDE tooling. Keep those chains high-risk and
# reviewable, but do not turn static capability evidence into a preventive block
# without observed behavior, authoritative intelligence, or a separate
# high-specificity data-theft chain.
BLOCKING_CORRELATED_RULES = CORRELATED_RULES - {
    "download-and-execute",
    "remote-vsix-install-chain",
    "destructive-transfer-chain",
    "environment-data-exfiltration",
    "persistence-chain",
    "hidden-remote-workspace-task",
}
BLOCKING_OBSERVED_RULES = {
    "observed-destructive-behavior",
    "observed-download-execute",
    "observed-persistence",
    "observed-secret-exfil",
}
DOWNLOAD_EXECUTE_CREDENTIAL_SIGNALS = {
    "credential-dataflow-to-file",
    "credential-dataflow-to-network",
    "credential-dataflow-to-process",
    "credential-exfiltration-chain",
    "credential-harvesting-exfiltration",
    "credential-identifier-flow-to-network",
    "obfuscated-credential-harvesting-exfiltration",
}
CAPABILITY_RULES = {
    "agent-filesystem-tool",
    "agent-network-tool",
    "agent-prompt-injection-sink",
    "agent-shell-tool",
    "agentic-tooling",
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
    "wasm-loader",
    "powerful-ide-contribution",
    "sensitive-activation",
    "startup-activation",
    "untrusted-input-execution",
    "webview-csp-missing",
    "webview-csp-unsafe-directive",
}
DEPENDENCY_RULES = {"mutable-dependency-source", "unpinned-dependency", "vulnerable-npm-dependency"}
PROVENANCE_RULES = {"marketplace-removed-package", "packed-artifact", "binary-without-origin"}
POSTURE_RULES = {
    "dangerous-github-workflow",
    "repo-binary-artifacts",
    "workflow-token-permissions-broad",
    "entrypoint-ast-unparsed",
    "executable-heavy-obfuscation",
}
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
    "remote-credential-broker",
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
    marketplace_target_platform: str | None = None,
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
    required_providers: set[str] | frozenset[str] | None = None,
    jobs: int = 1,
    marketplace_artifact_store: ArtifactStore | None = None,
    path_artifact_origin: str | None = None,
    artifact_url: str | None = None,
    artifact_sha256: str | None = None,
    dynamic_runtime: bool = False,
    runtime_timeout_seconds: int = 15,
) -> dict[str, Any]:
    if not 1 <= jobs <= 32:
        raise ValueError("jobs must be between 1 and 32")
    if not 1 <= runtime_timeout_seconds <= 300:
        raise ValueError("runtime_timeout_seconds must be between 1 and 300")
    request = ScanRequest.create(
        paths=paths,
        extension_ids=extension_ids,
        marketplace_scan_ids=marketplace_scan_ids,
        marketplace_version=marketplace_version,
        marketplace_target_platform=marketplace_target_platform,
        include_fixtures=include_fixtures,
        all_local=all_local,
        online=online,
        known_bad_hashes_file=known_bad_hashes_file,
        threat_feed_file=threat_feed_file,
        extension_advisories_file=extension_advisories_file,
        registry_snapshot_file=registry_snapshot_file,
        sandbox_observations_file=sandbox_observations_file,
        previous_report_file=previous_report_file,
        path_artifact_origin=path_artifact_origin,
        artifact_url=artifact_url,
        artifact_sha256=artifact_sha256,
        dynamic_runtime=dynamic_runtime,
        runtime_timeout_seconds=runtime_timeout_seconds,
        include_posture=include_posture,
        required_providers=required_providers,
    )
    return _scan_request(request, jobs=jobs, marketplace_artifact_store=marketplace_artifact_store)


def _scan_request(
    request: ScanRequest,
    *,
    jobs: int = 1,
    marketplace_artifact_store: ArtifactStore | None = None,
) -> dict[str, Any]:
    # Validate replayed intelligence before acquiring or scanning any artifact.
    # A malformed/tampered snapshot is a request-level failure; delaying this
    # check until after static analysis wastes work and can leave callers with
    # the misleading impression that a partial scan was useful.
    replayed_registry = (
        _load_registry_snapshot(request.registry_snapshot_file)
        if request.registry_snapshot_file is not None
        else None
    )
    targets: list[dict[str, str]] = []
    root = Path.cwd()

    if request.include_fixtures:
        targets.extend(discover_from_path(root / "fixtures"))
    if request.path_artifact_origin is not None and request.path_artifact_origin not in ARTIFACT_ORIGINS:
        raise ValueError(f"Unsupported path artifact origin: {request.path_artifact_origin}")
    for path in request.paths:
        discovered = discover_from_path(path)
        for target in discovered:
            origin = request.path_artifact_origin or (
                "user_uploaded_vsix" if target.get("type") == "vsix" else "local_directory"
            )
            if target.get("type") == "vsix" and origin in {"installed_directory", "local_directory", "source_snapshot"}:
                raise ValueError(f"Artifact origin {origin} cannot describe a VSIX file")
            if target.get("type") != "vsix" and origin in {"user_uploaded_vsix", "archive_artifact"}:
                raise ValueError(f"Artifact origin {origin} requires a VSIX file")
            target["artifact_origin"] = origin
        targets.extend(discovered)
    if request.all_local:
        installed = discover_local_installations()
        for target in installed:
            target["artifact_origin"] = "installed_directory"
        targets.extend(installed)

    unique: dict[str, dict[str, str]] = {}
    for target in targets:
        unique[target["path"]] = target

    known_bad_hashes = _load_known_bad_hashes(request.known_bad_hashes_file)
    local_targets = list(unique.values())
    extensions = _scan_discovered_targets(local_targets, known_bad_hashes, jobs=jobs)
    extensions.extend(_registry_only_extension(extension_id) for extension_id in request.extension_ids)
    runtime_bundle: dict[str, Any] = {
        "schema_version": "0.1.0",
        "mode": "executed",
        "extensions": {},
        "runs": [],
        "required_extension_ids": [],
        "external_syscall_trace": False,
        "external_syscall_trace_available": external_trace_available(),
    }
    if request.dynamic_runtime and local_targets:
        _apply_local_dynamic_runtime(
            local_targets,
            extensions[:len(local_targets)],
            runtime_bundle,
            request.runtime_timeout_seconds,
        )
    for identifier in request.marketplace_scan_ids:
        extensions.append(scan_marketplace_extension(
            identifier,
            version=request.marketplace_version,
            target_platform=request.marketplace_target_platform,
            known_bad_hashes=known_bad_hashes,
            artifact_store=marketplace_artifact_store,
            dynamic_runtime=request.dynamic_runtime,
            runtime_timeout_seconds=request.runtime_timeout_seconds,
            runtime_bundle=runtime_bundle if request.dynamic_runtime else None,
        ))
    _apply_threat_feed(extensions, _load_threat_feed(request.threat_feed_file))
    advisory_bundle = _load_extension_advisories(request.extension_advisories_file)
    if request.artifact_url or request.artifact_sha256:
        if not request.artifact_url or not request.artifact_sha256:
            raise ValueError("artifact_url and artifact_sha256 must be provided together")
        extensions.append(scan_remote_artifact(request.artifact_url, request.artifact_sha256, known_bad_hashes))
    _apply_extension_advisories(extensions, advisory_bundle)
    sandbox_bundle = _load_sandbox_observation_bundle(request.sandbox_observations_file)
    if request.dynamic_runtime:
        sandbox_bundle = _merge_dynamic_runtime_bundle(sandbox_bundle, runtime_bundle)
    _apply_sandbox_observations(extensions, sandbox_bundle["extensions"])
    _apply_sandbox_provider(extensions, sandbox_bundle)
    registry = replayed_registry or _capture_registry_snapshot(
        enrich_registry(extensions, online=request.online),
        source="live",
    )
    _apply_registry_findings(extensions, registry["findings"])
    dependency_errors = [
        item for item in registry.get("errors", [])
        if isinstance(item, dict) and str(item.get("source") or "").startswith("osv")
    ]
    registry_enabled = bool(registry.get("enabled"))
    registry_identity = registry.get("snapshot") if isinstance(registry.get("snapshot"), dict) else {}
    requested_providers = request.required_providers
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
        for provider_name in requested_providers:
            provider = providers.setdefault(
                provider_name,
                {
                    "provider": provider_name,
                    "status": "unavailable",
                    "error": "Required provider did not report a result",
                },
            )
            provider["required"] = True
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
            "payload": _registry_snapshot_payload(registry),
        },
        "dynamic_sandbox": dict(sandbox_bundle["metadata"]),
    }
    return _build_report(
        extensions,
        registry,
        _load_previous_report(request.previous_report_file),
        include_posture=request.include_posture,
        intelligence=intelligence,
    )


def _registry_snapshot_payload(registry: dict[str, Any]) -> dict[str, Any]:
    return _normalize_registry_snapshot_value({
        "enabled": bool(registry.get("enabled")),
        "mode": str(registry.get("mode") or "disabled"),
        "findings": list(registry.get("findings") or []),
        "errors": list(registry.get("errors") or []),
    })


def _normalize_registry_snapshot_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _normalize_registry_snapshot_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_registry_snapshot_value(item) for item in value]
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _capture_registry_snapshot(registry: dict[str, Any], *, source: str) -> dict[str, Any]:
    payload = _registry_snapshot_payload(registry)
    digest = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
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
    metadata = parsed.get("metadata") if isinstance(parsed.get("metadata"), dict) else {}
    metadata_intelligence = (
        metadata.get("intelligence_snapshot")
        if isinstance(metadata.get("intelligence_snapshot"), dict)
        else {}
    )
    scan = parsed.get("scan") if isinstance(parsed.get("scan"), dict) else {}
    scan_intelligence = (
        scan.get("intelligence_snapshot")
        if isinstance(scan.get("intelligence_snapshot"), dict)
        else {}
    )
    top_level_intelligence = parsed.get("intelligence") if isinstance(parsed.get("intelligence"), dict) else {}
    registry_intelligence = (
        metadata_intelligence.get("registry")
        if isinstance(metadata_intelligence.get("registry"), dict)
        else scan_intelligence.get("registry")
        if isinstance(scan_intelligence.get("registry"), dict)
        else top_level_intelligence.get("registry")
        if isinstance(top_level_intelligence.get("registry"), dict)
        else {}
    )
    candidate = (
        parsed.get("registry_checks")
        if isinstance(parsed.get("registry_checks"), dict)
        else registry_intelligence.get("payload")
        if isinstance(registry_intelligence.get("payload"), dict)
        else parsed
    )
    if not isinstance(candidate.get("findings"), list) or not isinstance(candidate.get("errors"), list):
        raise ValueError("Registry intelligence snapshot must include findings and errors arrays.")
    captured = _capture_registry_snapshot(candidate, source="replay")
    claimed = (
        candidate.get("snapshot")
        if isinstance(candidate.get("snapshot"), dict)
        else registry_intelligence
    )
    claimed_digest = str(claimed.get("sha256") or "")
    if claimed_digest and claimed_digest != captured["snapshot"]["sha256"]:
        raise ValueError("Registry intelligence snapshot digest does not match its contents.")
    return captured


def scan_extension(path: Path, source: str = "vscode", known_bad_hashes: dict[str, dict[str, Any]] | None = None) -> ExtensionReport:
    _enforce_extension_resource_budget(path)
    manifest, manifest_status = _read_manifest_status(path / "package.json")
    name = str(manifest.get("name") or path.name)
    publisher = str(manifest.get("publisher") or "unknown")
    version = str(manifest.get("version") or "0.0.0")
    extension_id = f"{publisher}.{name}"
    findings: list[Finding] = []
    capabilities: dict[str, dict[str, Any]] = {}
    scanned_files = 0
    source_previews: list[dict[str, Any]] = []
    js_ast_statuses: list[str] = []
    js_ast_failed_paths: list[str] = []
    ast_unparsed_entrypoints: list[str] = []

    _add_manifest_findings(extension_id, version, manifest, findings, capabilities)
    _add_dependency_source_findings(extension_id, version, manifest, findings)

    files = _walk_extension_files(path)
    entrypoints, optional_missing_entrypoints = _declared_entrypoints(manifest, path)
    artifact_inventory = _artifact_inventory(path, files)
    analysis_coverage = _new_analysis_coverage(files, entrypoints, path, optional_missing_entrypoints)
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
    captured_preview_paths: set[str] = set()
    module_summaries: list[dict[str, Any]] = []
    primary_readme = next(
        (
            candidate
            for candidate in sorted(files, key=lambda item: item.relative_to(path).as_posix().casefold())
            if _is_primary_readme(candidate.relative_to(path).as_posix())
        ),
        None,
    )
    if primary_readme is not None:
        rel = primary_readme.relative_to(path).as_posix()
        preview = _bounded_source_preview(primary_readme, rel)
        if preview is not None:
            source_previews.append(preview)
            captured_preview_paths.add(rel)
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
            if (
                _is_documentation_preview(rel)
                and rel not in captured_preview_paths
                and len(source_previews) < MAX_SOURCE_PREVIEWS
                and file.stat().st_size <= MAX_SOURCE_PREVIEW_BYTES
            ):
                preview = _bounded_source_preview(file, rel)
                if preview is not None:
                    source_previews.append(preview)
                    captured_preview_paths.add(rel)
            continue

        text = _read_text(file)
        if text is None:
            if suffix in EXEC_TEXT_EXTS:
                analysis_coverage["read_failures"].append(rel)
            continue
        if file.stat().st_size > MAX_TEXT_BYTES:
            analysis_coverage["oversized_files"].append(rel)
            continue
        text_size = file.stat().st_size
        if (
            rel not in captured_preview_paths
            and len(source_previews) < MAX_SOURCE_PREVIEWS
            and text_size <= MAX_SOURCE_PREVIEW_BYTES
        ):
            encoded_text = text.encode("utf-8")
            source_previews.append({
                "path": rel,
                "content": text,
                "content_sha256": hashlib.sha256(encoded_text).hexdigest(),
                "truncated": False,
            })
            captured_preview_paths.add(rel)
        scanned_files += 1
        # Run the bounded AST subprocess before expanding raw-text matches into
        # Python Finding objects. Large bundled entrypoints can otherwise push
        # the parent close to the container memory limit and starve Node's GC,
        # turning identical source into a resource-dependent timeout.
        if suffix in JS_AST_EXTS:
            generated_blob = _is_generated_code_blob(rel, text)
            semgrep_exclusion = _semgrep_scope_exclusion(text, text_size)
            if semgrep_exclusion:
                analysis_coverage["provider_scopes"]["semgrep"]["excluded_files"].append({
                    "path": rel,
                    "reason": semgrep_exclusion,
                })
            else:
                analysis_coverage["provider_scopes"]["semgrep"]["eligible_files"].append(rel)
            ast_budget_allows_entrypoint = (
                not is_entrypoint
                or not generated_blob
                or text_size <= GENERATED_ENTRYPOINT_AST_MAX_BYTES
            )
            if ast_budget_allows_entrypoint:
                status = _add_ast_findings(extension_id, version, rel, text, findings, generated=generated_blob)
                js_ast_statuses.append(status)
                if status not in ("ok", "unparsed"):
                    js_ast_failed_paths.append(rel)
                if is_entrypoint and status == "unparsed":
                    ast_unparsed_entrypoints.append(rel)
            else:
                js_ast_statuses.append("generated-resource-skipped")
                js_ast_failed_paths.append(rel)
        if suffix in EXEC_TEXT_EXTS:
            analysis_coverage["analyzed_executable_files"].append(rel)
            if suffix in JS_AST_EXTS:
                module_summaries.append(module_summary(rel, text, analyze_imports=not generated_blob))
            _add_code_findings(
                extension_id,
                version,
                rel,
                text,
                findings,
                capabilities,
                is_entrypoint=is_entrypoint,
            )
            _add_workspace_cli_path_findings(extension_id, version, manifest, [(rel, text)], findings)
        if suffix in EXEC_TEXT_EXTS or suffix in {".html", ".htm"}:
            _add_webview_csp_findings(
                extension_id,
                version,
                rel,
                text,
                findings,
                report_missing=not (suffix in JS_AST_EXTS and _is_generated_code_blob(rel, text)),
            )

    flow_entrypoints = {item for item in entrypoints if Path(item).suffix.lower() in JS_AST_EXTS}
    module_flow_status = {
        "provider": "module_flow",
        "status": "completed",
        "required": True,
        "modules": len(module_summaries),
        "entrypoints": sorted(flow_entrypoints),
        "max_modules": MAX_FLOW_MODULES,
        "max_depth": MAX_FLOW_DEPTH,
        "max_paths": MAX_FLOW_PATHS,
    }
    try:
        flow_coverage = module_flow_coverage(module_summaries, flow_entrypoints)
        module_flow_status.update(flow_coverage)
        if flow_coverage["unresolved_executable_import_count"]:
            module_flow_status.update({
                "status": "failed",
                "error": "reachable relative executable imports could not be resolved",
                "error_count": flow_coverage["unresolved_executable_import_count"],
            })
        cross_file_vsix_flow = remote_vsix_install_flow(module_summaries, flow_entrypoints)
        cross_file_credential_flow = credential_exfiltration_flow(module_summaries, flow_entrypoints)
    except FlowAnalysisLimitError as exc:
        cross_file_vsix_flow = None
        cross_file_credential_flow = None
        module_flow_status.update({"status": "failed", "error": str(exc), "error_count": 1})
    if cross_file_vsix_flow:
        findings.append(_finding(
            extension_id,
            version,
            "remote-vsix-install-chain",
            "execution",
            "HIGH",
            0.92,
            "Import-connected modules download, write, and install a remote VSIX without visible integrity verification.",
            cross_file_vsix_flow["files"],
            "Block silent remote extension installation or require independently trusted integrity verification and explicit approval.",
            {
                "evidence_class": "correlated",
                "correlation": "cross-file-import-connected-semantic-chain",
                "source": "remote-download",
                "transform": "local-vsix-write",
                "sink": "workbench.extensions.installExtension",
                "integrity_verification": False,
                "stages": cross_file_vsix_flow["stages"],
                "import_path": cross_file_vsix_flow["import_path"],
            },
        ))

    if cross_file_credential_flow:
        findings.append(_finding(
            extension_id,
            version,
            "credential-harvesting-exfiltration",
            "credential-access",
            "HIGH",
            0.95,
            "A directed module path reads multiple credential families, serializes collected data, and writes it to a network request body.",
            cross_file_credential_flow["files"],
            "Block the extension and investigate the credential sources, transformations, and destination.",
            {
                "evidence_class": "correlated",
                "correlation": "cross-file-import-directed-semantic-chain",
                "source": "multi-family-credential-file-read",
                "transform": "serialization",
                "sink": "network-request-body",
                "credential_families": cross_file_credential_flow["credential_families"],
                "stages": cross_file_credential_flow["stages"],
                "import_path": cross_file_credential_flow["import_path"],
            },
        ))

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


    provider_findings, provider_statuses = run_static_providers(
        path,
        extension_id,
        version,
        targets=_static_provider_targets(files, path, analysis_coverage),
    )
    findings.extend(provider_findings)
    findings = _dedupe_findings(findings)
    semgrep_scope = analysis_coverage["provider_scopes"]["semgrep"]
    provider_statuses["semgrep"].update({
        "scope": (
            "source-like JavaScript/TypeScript up to "
            f"{SEMGREP_MAX_TARGET_BYTES:,} bytes per file"
        ),
        "eligible_file_count": len(semgrep_scope["eligible_files"]),
        "excluded_file_count": len(semgrep_scope["excluded_files"]),
    })
    analysis_coverage["providers"] = {
        "native_static": {"provider": "native_static", "status": "completed", "required": True},
        "javascript_ast": _javascript_ast_provider_status(js_ast_statuses, js_ast_failed_paths),
        "module_flow": module_flow_status,
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


def scan_vsix(
    path: Path,
    known_bad_hashes: dict[str, dict[str, Any]] | None = None,
    artifact_origin: str = "user_uploaded_vsix",
) -> ExtensionReport:
    if artifact_origin not in ARTIFACT_ORIGINS:
        raise ValueError(f"Unsupported VSIX artifact origin: {artifact_origin}")
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
            report.artifact_inventory["artifact_origin"] = artifact_origin
            report.artifact_inventory["vsix_signature"] = _vsix_signature_status(tmp_root)
            _record_archive_anomalies(report, archive_anomalies)
            report.instance_id = _stable_id(
                f"vsix:{vsix_hash}:{report.extension_id.lower()}:{report.version}"
            )
            report.artifact_identity = {
                "extension_id": report.extension_id,
                "version": report.version,
                "sha256": vsix_hash,
                "source": "vsix",
                "artifact_origin": artifact_origin,
                "original_registry_artifact": False,
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
            return scan_vsix(
                path,
                known_bad_hashes=known_bad_hashes,
                artifact_origin=target.get("artifact_origin", "user_uploaded_vsix"),
            )
        report = scan_extension(path, source=target.get("type", "vscode"), known_bad_hashes=known_bad_hashes)
        origin = target.get("artifact_origin", "local_directory")
        report.artifact_inventory["artifact_origin"] = origin
        report.artifact_identity.update({"artifact_origin": origin, "original_registry_artifact": False})
        return report
    except Exception as exc:  # noqa: BLE001 - isolate any per-artifact failure
        return _local_error_extension(path, target.get("type", "vscode"), f"{type(exc).__name__}: {exc}")


def _scan_discovered_targets(
    targets: list[dict[str, str]],
    known_bad_hashes: dict[str, dict[str, Any]],
    *,
    jobs: int,
) -> list[ExtensionReport]:
    """Scan local artifacts with deterministic, bounded parallelism."""
    if not targets:
        return []
    if jobs <= 1 or len(targets) == 1:
        return [_scan_discovered_target(target, known_bad_hashes) for target in targets]
    try:
        with ProcessPoolExecutor(max_workers=min(jobs, len(targets))) as executor:
            return list(
                executor.map(
                    _scan_discovered_target,
                    targets,
                    repeat(known_bad_hashes),
                    chunksize=1,
                )
            )
    except PermissionError:
        # Some managed runtimes deny the forkserver socket even though the
        # per-artifact scanners and their provider subprocesses are usable.
        # Preserve a truthful scan by retrying sequentially; this is a
        # capacity fallback, not a relaxation of analysis or isolation.
        return [_scan_discovered_target(target, known_bad_hashes) for target in targets]


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
    # Preserve trustworthy local identity even when the isolated worker dies
    # before it can produce a normal report. This is deliberately bounded and
    # manifest-only: it never turns a failed scan into a successful one and
    # does not inspect executable code on the failure path.
    manifest, _manifest_status = _read_manifest_status(path / "package.json") if path.is_dir() else ({}, "missing")
    publisher = str(manifest.get("publisher") or "").strip()
    package_name = str(manifest.get("name") or "").strip()
    version = str(manifest.get("version") or "").strip()
    identity = f"{publisher}.{package_name}" if publisher and package_name else ""
    name = package_name or path.name or "unknown"
    extension_id = identity or f"unknown.{name}"
    return ExtensionReport(
        instance_id=_stable_id(str(path)),
        extension_id=extension_id,
        name=name,
        publisher=publisher or "unknown",
        version=version or "unknown",
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


_DYNAMIC_RUNTIME_CAPABILITIES = frozenset({
    "agentic",
    "credential_commands",
    "credential_configuration",
    "credential_input",
    "dynamic_code",
    "lifecycle_scripts",
    "native_code",
    "network",
    "process_execution",
    "wasm_runtime",
})

# An activation process that exits unsuccessfully did not complete the
# required runtime contract, even if it emitted some authenticated events
# first. Keep the event as evidence, but do not let the receipt become
# publication-complete. Lifecycle-script failures are intentionally excluded:
# they are a separate contextual observation and the activation probe still
# runs afterward.
_RUNTIME_COVERAGE_FAILURE_KINDS = frozenset({
    "runtime_timeout",
    "sandbox_error",
    "runtime_entrypoint_error",
})


def _runtime_required_for_report(report: ExtensionReport) -> bool:
    """Require dynamic coverage only when it can answer a security question.

    A resolvable activation entrypoint is itself an executable trust boundary.
    Running it in the sandbox gives the scanner a chance to observe behavior
    that static rules did not recognize, so a missing capability label cannot
    silently turn into a false negative. Purely declarative packages such as
    themes remain ``not-applicable`` when they ship no executable entrypoint.

    Sensitive capabilities remain runtime-required even when no activation
    entrypoint is declared, which covers native/WASM payloads and lifecycle
    behavior discovered from the package. This is deliberately capability
    based rather than name based: a theme carrying a hidden native payload or
    network/process behavior still enters the required runtime path.
    """
    capability_ids = {
        str(item.get("id") or "")
        for item in report.capabilities
        if isinstance(item, dict)
    }
    if capability_ids & _DYNAMIC_RUNTIME_CAPABILITIES:
        return True
    coverage = report.analysis_coverage if isinstance(report.analysis_coverage, dict) else {}
    return bool(coverage.get("resolved_entrypoints"))


def _runtime_instance_key(report: ExtensionReport) -> str:
    """Return the collision-resistant key used for per-installation runtime evidence."""
    return str(report.instance_id or f"{report.extension_id}@{report.version}")


def _runtime_observations_for_report(
    observations: dict[str, list[dict[str, Any]]],
    report: ExtensionReport,
) -> list[dict[str, Any]]:
    """Read instance-keyed evidence with a legacy extension-ID fallback."""
    instance_key = _runtime_instance_key(report)
    if instance_key in observations:
        value = observations[instance_key]
        return value if isinstance(value, list) else []
    value = observations.get(report.extension_id, [])
    return value if isinstance(value, list) else []


def _runtime_bundle_key(bundle: dict[str, Any], report: ExtensionReport) -> str:
    """Preserve the legacy ID key until a duplicate installation needs disambiguation."""
    extensions = bundle.get("extensions") if isinstance(bundle.get("extensions"), dict) else {}
    if report.extension_id not in extensions:
        return report.extension_id
    return _runtime_instance_key(report)


def _finalize_runtime_trace_metadata(runtime_bundle: dict[str, Any]) -> None:
    """Summarize actual trace evidence without confusing it with availability."""
    runs = runtime_bundle.get("runs") if isinstance(runtime_bundle.get("runs"), list) else []
    required_runs = [
        item for item in runs
        if isinstance(item, dict) and item.get("required") is True
    ]
    runtime_bundle["external_syscall_trace"] = bool(
        required_runs
        and all(item.get("external_syscall_trace") is True for item in required_runs)
    )


def _runtime_execution_failure(runtime: dict[str, Any], items: list[dict[str, Any]]) -> str:
    """Explain when a required runtime pass did not execute an artifact path.

    Native/WASM and lifecycle capabilities can make runtime coverage required
    even when the package has no Node activation entrypoint. The sandbox still
    returns a valid plan in that case, but a plan-only result must not be
    mistaken for executed coverage. A successful lifecycle action is a valid
    execution path; otherwise the required provider is incomplete.
    """
    plan = runtime.get("plan") if isinstance(runtime.get("plan"), dict) else {}
    dependencies = plan.get("runtime_dependencies") if isinstance(plan.get("runtime_dependencies"), list) else []
    failed_dependencies = [
        item for item in dependencies
        if isinstance(item, dict)
        and item.get("required") is True
        and str(item.get("status") or "") not in {"packaged", "provisioned"}
    ]
    if failed_dependencies:
        dependency = failed_dependencies[0]
        name = str(dependency.get("dependency") or "required runtime sidecar")
        status = str(dependency.get("status") or "unknown")
        return f"Required runtime sidecar {name} was not verified ({status})."
    instrumentation = plan.get("instrumentation") if isinstance(plan.get("instrumentation"), dict) else {}
    entrypoint_status = str(instrumentation.get("entrypoint_status") or "")
    if entrypoint_status != "not-applicable":
        return ""
    lifecycle_executed = any(
        isinstance(item, dict)
        and item.get("kind") == "lifecycle_executed"
        and item.get("returncode") == 0
        for item in items
    )
    if lifecycle_executed:
        return ""
    return (
        "Required runtime coverage had no declared Node activation entrypoint "
        "and did not complete a lifecycle execution path."
    )


def _apply_local_dynamic_runtime(
    targets: list[dict[str, str]],
    extensions: list[ExtensionReport],
    runtime_bundle: dict[str, Any],
    timeout_seconds: int,
) -> None:
    """Run the same capability-gated sandbox for local VSIX and directory inputs.

    Marketplace scans already use this path in ``scan_marketplace_extension``.
    Keeping local artifacts on the same runtime path prevents ``--runtime`` from
    being a misleading no-op for uploaded VSIX files and installed extensions.
    """
    for target, report in zip(targets, extensions, strict=False):
        required = _runtime_required_for_report(report)
        instance_key = _runtime_instance_key(report)
        bundle_key = _runtime_bundle_key(runtime_bundle, report)
        run_record: dict[str, Any] = {
            "instance_id": instance_key,
            "extension_id": report.extension_id,
            "version": report.version,
            "required": required,
            "artifact_sha256": report.artifact_hash,
            "status": "not-applicable" if not required else "failed",
            "external_syscall_trace": False,
        }
        if required:
            runtime_bundle.setdefault("required_extension_ids", []).append(report.extension_id)
            runtime_bundle.setdefault("runtime_required_instances", []).append(instance_key)
            try:
                runtime = run_sandbox(
                    Path(target["path"]),
                    allow_execute=True,
                    timeout_seconds=timeout_seconds,
                )
                observed = runtime.get("extensions", {}) if isinstance(runtime, dict) else {}
                items = _runtime_observations_for_report(observed, report) if isinstance(observed, dict) else []
                runtime_failed = any(
                    isinstance(item, dict)
                    and str(item.get("kind") or "") in _RUNTIME_COVERAGE_FAILURE_KINDS
                    for item in items
                )
                execution_error = _runtime_execution_failure(runtime, items) if required else ""
                if execution_error:
                    items.append({
                        "kind": "sandbox_error",
                        "phase": "runtime",
                        "evidence": execution_error,
                    })
                    runtime_failed = True
                runtime_bundle.setdefault("extensions", {})[bundle_key] = [
                    item for item in items if isinstance(item, dict)
                ]
                run_record.update({
                    "status": "failed" if runtime_failed else "completed",
                    "mode": runtime.get("mode") if isinstance(runtime, dict) else "executed",
                    "observation_count": len(items),
                })
                if isinstance(runtime, dict):
                    plan = runtime.get("plan") if isinstance(runtime.get("plan"), dict) else {}
                    instrumentation = plan.get("instrumentation") if isinstance(plan.get("instrumentation"), dict) else {}
                    trace = instrumentation.get("external_syscall_trace")
                    trace_available = (
                        isinstance(trace, dict)
                        and trace.get("requested") is True
                        and trace.get("available") is True
                    )
                    if trace_available:
                        runtime_bundle["external_syscall_trace_available"] = True
                    run_record["external_syscall_trace"] = bool(trace_available and not runtime_failed)
                if runtime_failed:
                    run_record["error"] = execution_error or "Runtime execution did not complete successfully."
            except Exception as exc:  # noqa: BLE001 - runtime failure is disclosed and fail-closed
                runtime_bundle.setdefault("extensions", {})[bundle_key] = [{
                    "kind": "sandbox_error",
                    "phase": "runtime",
                    "evidence": str(exc)[:500],
                }]
                run_record["error"] = str(exc)[:500]
        runtime_bundle.setdefault("runs", []).append(run_record)
        _finalize_runtime_trace_metadata(runtime_bundle)


def scan_marketplace_extension(
    identifier: str,
    version: str | None = None,
    target_platform: str | None = None,
    known_bad_hashes: dict[str, dict[str, Any]] | None = None,
    artifact_store: ArtifactStore | None = None,
    dynamic_runtime: bool = False,
    runtime_timeout_seconds: int = 15,
    runtime_bundle: dict[str, Any] | None = None,
) -> ExtensionReport:
    """Acquire an exact marketplace artifact and analyze it.

    Static analysis is always performed. When ``dynamic_runtime`` is explicit,
    executable-capability artifacts also receive a bounded Bubblewrap pass over
    the preserved exact bytes. Themes and other non-executable packages are
    recorded as policy-gated/not-applicable instead of being forced through a
    meaningless default entrypoint.
    """
    try:
        resolved_id = parse_marketplace_reference(identifier)
    except MarketplaceDownloadError as exc:
        return _marketplace_error_extension(identifier, str(exc))

    registry_source: dict[str, str] = {}
    try:
        vsix_path = download_marketplace_vsix(
            resolved_id,
            version=version,
            target_platform=target_platform,
            registry_out=registry_source,
        )
    except MarketplaceDownloadError as exc:
        return _marketplace_error_extension(resolved_id, str(exc))

    stored: StoredArtifact | None = None
    try:
        configured_store = artifact_store if artifact_store is not None else artifact_store_from_environment()
        scan_path = vsix_path
        if configured_store is not None:
            stored = configured_store.preserve(
                vsix_path,
                extension_id=registry_source.get("extension_id", resolved_id),
                version=registry_source.get("version", version or ""),
                registry=registry_source.get("registry", "vs-marketplace"),
                target_platform=registry_source.get("target_platform", target_platform or ""),
            )
            scan_path = stored.path
        report = scan_vsix(scan_path, known_bad_hashes=known_bad_hashes, artifact_origin="archive_artifact")
        if dynamic_runtime and runtime_bundle is not None:
            runtime_required = _runtime_required_for_report(report)
            instance_key = _runtime_instance_key(report)
            bundle_key = _runtime_bundle_key(runtime_bundle, report)
            run_record: dict[str, Any] = {
                "instance_id": instance_key,
                "extension_id": report.extension_id,
                "version": report.version,
                "required": runtime_required,
                "artifact_sha256": report.artifact_hash,
                "status": "not-applicable" if not runtime_required else "failed",
                "external_syscall_trace": False,
            }
            if runtime_required:
                runtime_bundle.setdefault("required_extension_ids", []).append(report.extension_id)
                runtime_bundle.setdefault("runtime_required_instances", []).append(instance_key)
                try:
                    runtime = run_sandbox(
                        scan_path,
                        allow_execute=True,
                        timeout_seconds=runtime_timeout_seconds,
                    )
                    observed = runtime.get("extensions", {}) if isinstance(runtime, dict) else {}
                    items = _runtime_observations_for_report(observed, report) if isinstance(observed, dict) else []
                    runtime_failed = any(
                        isinstance(item, dict)
                        and str(item.get("kind") or "") in _RUNTIME_COVERAGE_FAILURE_KINDS
                        for item in items
                    )
                    execution_error = _runtime_execution_failure(runtime, items) if runtime_required else ""
                    if execution_error:
                        items.append({
                            "kind": "sandbox_error",
                            "phase": "runtime",
                            "evidence": execution_error,
                        })
                        runtime_failed = True
                    runtime_bundle.setdefault("extensions", {})[bundle_key] = [
                        item for item in items if isinstance(item, dict)
                    ]
                    run_record.update({
                        "status": "failed" if runtime_failed else "completed",
                        "mode": runtime.get("mode") if isinstance(runtime, dict) else "executed",
                        "observation_count": len(items),
                    })
                    if isinstance(runtime, dict):
                        plan = runtime.get("plan") if isinstance(runtime.get("plan"), dict) else {}
                        instrumentation = plan.get("instrumentation") if isinstance(plan.get("instrumentation"), dict) else {}
                        trace = instrumentation.get("external_syscall_trace")
                        trace_available = (
                            isinstance(trace, dict)
                            and trace.get("requested") is True
                            and trace.get("available") is True
                        )
                        if trace_available:
                            runtime_bundle["external_syscall_trace_available"] = True
                        run_record["external_syscall_trace"] = bool(trace_available and not runtime_failed)
                    if runtime_failed:
                        run_record["error"] = execution_error or "Runtime execution did not complete successfully."
                except Exception as exc:  # noqa: BLE001 - runtime failures become disclosed provider evidence
                    runtime_bundle.setdefault("extensions", {})[bundle_key] = [{
                        "kind": "sandbox_error",
                        "phase": "runtime",
                        "evidence": str(exc)[:500],
                    }]
                    run_record["error"] = str(exc)[:500]
            runtime_bundle.setdefault("runs", []).append(run_record)
            _finalize_runtime_trace_metadata(runtime_bundle)
    except ArtifactStoreError as exc:
        return _marketplace_error_extension(resolved_id, f"Downloaded VSIX could not be preserved: {exc}")
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
    report.artifact_identity.update({
        "registry": report.source,
        "artifact_origin": f"{report.source}_original",
        "original_registry_artifact": True,
        "target_platform": registry_source.get("target_platform", target_platform or ""),
        "preserved": stored is not None,
    })
    report.artifact_inventory["artifact_origin"] = f"{report.source}_original"
    _apply_marketplace_integrity(report, registry_source)
    if stored is not None:
        storage = {
            "backend": stored.backend, "storage_key": stored.storage_key,
            "sha256": stored.sha256, "size_bytes": stored.size_bytes,
            "first_seen": stored.first_seen, "last_seen": stored.last_seen,
        }
        report.artifact_identity["storage"] = storage
        report.artifact_inventory["artifact_storage"] = storage
    return report


def scan_remote_artifact(
    url: str,
    expected_sha256: str,
    known_bad_hashes: dict[str, dict[str, Any]] | None = None,
) -> ExtensionReport:
    """Acquire and scan a hash-pinned non-registry VSIX without trusting its claimed origin."""
    try:
        path = acquire_https_vsix(url, expected_sha256)
    except ArtifactInputError as exc:
        return _local_error_extension(Path("remote-artifact.vsix"), "artifact-url-error", str(exc))
    try:
        report = scan_vsix(path, known_bad_hashes=known_bad_hashes, artifact_origin="archive_artifact")
        report.install_path = "artifact-url:[redacted]"
        report.artifact_identity.update({
            "artifact_origin": "archive_artifact",
            "original_registry_artifact": False,
            "expected_sha256": expected_sha256.lower(),
            "sha256_verified": report.artifact_hash == expected_sha256.lower(),
        })
        report.artifact_inventory["artifact_origin"] = "archive_artifact"
        return report
    finally:
        path.unlink(missing_ok=True)


def _apply_marketplace_integrity(report: ExtensionReport, registry_source: dict[str, str]) -> None:
    expected_sha256 = registry_source.get("expected_sha256", "").lower()
    sha256_verified = registry_source.get("sha256_verified") == "true"
    integrity_mismatch = registry_source.get("integrity_mismatch") == "true"
    signature_declared = registry_source.get("signature_asset_declared") == "true"
    metadata_matches = registry_source.get("integrity_metadata_matches_artifact") == "true"
    signature = {
        "present": signature_declared,
        "verified": False,
        "verification_supported": False,
        "source": "marketplace-detached-asset" if signature_declared else "marketplace-metadata",
        "reason": (
            "detached-signature-declared-but-not-cryptographically-verified"
            if signature_declared
            else "no-detached-signature-declared"
            if metadata_matches
            else "exact-artifact-signature-metadata-unavailable"
        ),
        "metadata_matches_artifact": metadata_matches,
        "package_integrity": {
            "algorithm": "sha256",
            "expected": expected_sha256,
            "actual": report.artifact_hash,
            "matched": bool(expected_sha256 and sha256_verified and expected_sha256 == report.artifact_hash),
            "source": "vs-marketplace-version-property" if expected_sha256 else "unavailable",
            "metadata_mismatch": integrity_mismatch,
        },
    }
    report.artifact_inventory["vsix_signature"] = signature
    report.artifact_identity["signature"] = dict(signature)
    if integrity_mismatch:
        warning = (
            "The Marketplace version metadata SHA-256 did not match the exact bytes served. "
            "The scanned artifact is identified by its observed SHA-256, but registry integrity "
            "metadata is not verified."
        )
        report.artifact_inventory.setdefault("warnings", []).append(warning)
        report.artifact_identity["registry_integrity_mismatch"] = True


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
    theme_surfaces = [
        key for key in ("themes", "iconThemes", "productIconThemes")
        if key in contributes
    ]
    if theme_surfaces:
        # Manifest contribution is stronger than a name/description keyword:
        # icon packs and color themes often call themselves "icons" or use a
        # publisher brand, while their actual IDE surface is declarative.
        capabilities.setdefault("theme_surface", {"id": "theme_surface", "evidence": []})["evidence"].extend(theme_surfaces)
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
    native_without_origin: list[dict[str, Any]] = []
    for artifact in artifact_inventory["risky_artifacts"]:
        rel = str(artifact["path"])
        kind = str(artifact["kind"])
        if kind == "native":
            native_artifacts.append(artifact)
            capabilities.setdefault("native_code", {"id": "native_code", "evidence": []})["evidence"].append(rel)
            if not _has_origin_evidence(path, rel, all_paths):
                native_without_origin.append(artifact)
        else:
            packed_artifacts.append(artifact)
            capabilities.setdefault("packed_artifacts", {"id": "packed_artifacts", "evidence": []})["evidence"].append(rel)

    # Origin verification is not independent intelligence yet: the scanner
    # cannot authenticate a package-controlled README, checksum, or signature
    # against a vendor trust root. Keep the gap visible, but aggregate it into
    # one bounded hardening note and never turn every bundled language-server
    # binary into a separate review event.
    if native_without_origin:
        sample = native_without_origin[:20]
        sample_paths = [str(a["path"]) for a in sample]
        findings.append(_finding(
            extension_id,
            version,
            "binary-without-origin",
            "provenance",
            "MEDIUM",
            0.55,
            (
                f"{len(native_without_origin)} native artifact(s) lack independent origin verification."
                f" Sample: {', '.join(sample_paths)}."
            ),
            sample_paths,
            "Use a registry-backed signature or attestation when available; otherwise document the build origin and keep the artifact under release monitoring.",
            {
                "unverified_count": len(native_without_origin),
                "sample_artifacts": _artifact_evidence(sample),
                "verification_status": "not_independently_verified",
            },
        ))

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

    # WebAssembly is executable code even when it is opaque to the JavaScript
    # text analyzers. Treat the presence of a module as a runtime capability,
    # not as malware evidence. A separate contextual finding is emitted only
    # when an executable text file visibly instantiates or loads the module;
    # this catches loader-style supply-chain payloads without flagging every
    # legitimate language tool that ships WASM.
    wasm_paths = [
        str(item.get("path"))
        for item in artifact_inventory.get("_all_file_hashes", [])
        if isinstance(item, dict) and str(item.get("path") or "").lower().endswith(".wasm")
    ]
    if wasm_paths:
        capabilities.setdefault("wasm_runtime", {"id": "wasm_runtime", "evidence": []})["evidence"].extend(wasm_paths[:20])
        loader_paths: list[str] = []
        if path is not None:
            candidates = [
                item for item in artifact_inventory.get("_all_file_hashes", [])
                if isinstance(item, dict)
                and str(item.get("path") or "").lower().rsplit(".", 1)[-1] in {"js", "cjs", "mjs", "ts", "tsx", "jsx"}
                and int(item.get("size_bytes") or 0) <= MAX_TEXT_BYTES
            ]
            for item in candidates[:2_000]:
                rel = str(item.get("path") or "")
                text = _read_text(path / rel)
                if text and WASM_LOADER_RE.search(text):
                    loader_paths.append(rel)
                    if len(loader_paths) >= 20:
                        break
        if loader_paths:
            findings.append(_finding(
                extension_id,
                version,
                "wasm-loader",
                "artifact",
                "MEDIUM",
                0.65,
                f"Extension ships {len(wasm_paths)} WebAssembly module(s) and executable code that loads or instantiates one.",
                sorted(set(wasm_paths[:20] + loader_paths)),
                "Require the controlled runtime pass and verify the module's origin, imports, and any network or process behavior before approval.",
                {
                    "wasm_files": wasm_paths[:20],
                    "loader_files": loader_paths,
                    "loader_detection": "visible-WebAssembly-instantiation-or-wasm-load",
                },
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
    *,
    is_entrypoint: bool = False,
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
    has_content_download = _has_content_download(text)
    has_obfuscation = bool(re.search(r"(atob\(|buffer\.from\([^)]*,\s*['\"]base64['\"]|fromcharcode|\\x[0-9a-f]{2})", text, re.I))
    has_dynamic_exec = bool(_DYNAMIC_EVAL_RE.search(text)) or bool(
        aliased_process_re and aliased_process_re.search(text)
    )
    has_exec_file = bool(re.search(r"\b(?:execFile|execFileSync)\s*\(", text)) or bool(
        aliased_process_methods & {"execFile", "execFileSync"}
    )
    has_shell_exec = bool(_SHELL_EXEC_RE.search(text)) or bool(aliased_process_methods & {"exec", "execSync"})
    has_configured_cli = has_exec_file and bool(re.search(r"getConfiguration\(|config\.get\(|executablePath|cliPath", text))
    has_editor_input = bool(re.search(r"activeTextEditor|document\.getText|selection|workspace\.workspaceFolders|uri\.fsPath|fileName", text))
    has_persistence = bool(re.search(r"(\.bashrc|\.zshrc|\.profile|crontab|launchagents|runonce|scheduledtask|systemd|update_rc|startup\s*folder)", text, re.I))
    remote_vsix_install_re = re.compile(
        r"(?:workbench\.extensions\.installExtension|commands\.executeCommand\s*\(\s*['\"]workbench\.extensions\.installExtension)",
        re.I,
    )
    has_remote_vsix_install = bool(remote_vsix_install_re.search(text))
    has_integrity_verification = has_integrity_gate(text)
    # A standalone "mcp" token is common in documentation, error messages, and
    # word lists. Require an actual agent API or protocol identifier before using
    # it as one leg of an exfiltration chain.
    has_agent_surface = bool(re.search(
        r"(?:languageModel|chatParticipant|toolInvocation|invokeTool|mcpServer|@modelcontextprotocol|register(?:Tool|ChatParticipant))",
        text,
        re.I,
    ))
    remote_broker_re = re.compile(
        r"\b(?:tokenServerUrl|remoteTokenServerUrl|remoteTokenServer|lease-token|report-result|remote-token)\b",
        re.I,
    )
    token_material_re = re.compile(
        r"\b(?:refreshToken|refresh_token|accessToken|access_token|tokenServerSecret|tokenInfo)\b",
        re.I,
    )
    bearer_forward_re = re.compile(
        r"(?:\b(?:authorization|Authorization)\b.{0,160}\bBearer\b|\bBearer\b.{0,160}\b(?:authorization|Authorization)\b)",
        re.I | re.S,
    )
    secret_regex = _combined_secret_regex(secret_refs)

    identifier_credential_flow = credential_value_flow(text)
    if identifier_credential_flow:
        findings.append(_finding(
            extension_id,
            version,
            "credential-identifier-flow-to-network",
            "credential-access",
            "HIGH",
            0.94,
            "A credential-file value flows through identifier assignments into an outbound request body.",
            [rel],
            "Block the extension and inspect the exact credential source and outbound destination.",
            {"evidence_class": "correlated", **identifier_credential_flow},
        ))

    environment_data_flow = _has_environment_data_network_flow(text)
    if environment_data_flow:
        findings.append(_finding(
            extension_id,
            version,
            "environment-data-exfiltration",
            "credential-access",
            "HIGH",
            0.93,
            "Whole-process environment data is collected or serialized and reaches an outbound request.",
            [rel],
            "Review the exact environment fields, destination, user disclosure, and whether the transfer is necessary. Sending the complete process environment is not ordinary telemetry.",
            {"evidence_class": "correlated", **environment_data_flow},
        ))

    # Credential stealers commonly split collection and transmission across
    # helper functions specifically to defeat same-window scanners.  Require a
    # deliberately narrow combination before correlating package-wide: several
    # independent credential families, recursive/home-directory collection,
    # serialization, and an explicit outbound write.  This catches systematic
    # harvesting without promoting ordinary authenticated API clients or tools
    # that read a single credential file.
    if _has_systematic_credential_harvesting_exfiltration(text, secret_refs):
        findings.append(_finding(
            extension_id,
            version,
            "credential-harvesting-exfiltration",
            "credential-access",
            "HIGH",
            0.93,
            "Code systematically collects multiple credential families and serializes them to an outbound request.",
            [rel],
            "Block the extension and investigate the collection paths and network destinations.",
            {
                "evidence_class": "correlated",
                "correlation": "same-file-interprocedural-semantic-chain",
                "credential_families": sorted(secret_id for secret_id, _ in secret_refs),
            },
        ))

    # Generated bundles routinely contain a generic fetch helper, workspace
    # writes, and a user-confirmed `installExtension` command in unrelated
    # modules.  File-wide co-occurrence turned that shape into a high-severity
    # updater finding (for example Red Hat YAML), even though no VSIX ever
    # crossed the three stages.  Require the three legs to be locally connected
    # around the install sink; the directed module-flow pass handles genuinely
    # split updater implementations separately.
    has_connected_remote_vsix_install = _features_nearby(
        text,
        [remote_vsix_install_re, DOWNLOAD_RE, FILE_WRITE_RE],
    )
    if has_connected_remote_vsix_install and not has_integrity_verification:
        findings.append(_finding(
            extension_id,
            version,
            "remote-vsix-install-chain",
            "execution",
            "HIGH",
            0.9,
            "Code downloads a VSIX, writes it locally, and invokes the IDE extension installer without visible integrity verification.",
            [rel],
            "Review the download source and require an independently trusted signature/hash plus explicit user approval before installation.",
            {
                "evidence_class": "correlated",
                "correlation": "same-file-semantic-chain",
                "source": "remote-download",
                "transform": "local-vsix-write",
                "sink": "workbench.extensions.installExtension",
                "integrity_verification": False,
            },
        ))

    # A background workspace task that launches a remote GitHub commit through
    # npx is materially different from ordinary shell/terminal capability.
    # Keep this high-specificity and review-only: a legitimate agent or setup
    # tool may intentionally do it, but the combination of remote code,
    # workspace execution, and hidden presentation deserves approval review.
    remote_github_npx_re = re.compile(
        r"\bnpx\s+-y\s+github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#(?:[0-9a-f]{40}|\$\{[A-Za-z_$][\w$]*\})",
        re.I,
    )
    remote_commit_hash_re = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.I)
    hidden_workspace_task_re = re.compile(
        r"(?:install-mcp-extension|mcpExtensionInstalledSha|presentationOptions\.focus\s*=\s*!1)",
        re.I,
    )
    remote_github_npx_match = remote_github_npx_re.search(text)
    hidden_workspace_task_matches = hidden_workspace_task_re.findall(text)
    if (
        remote_github_npx_match
        and remote_commit_hash_re.search(text)
        and hidden_workspace_task_matches
        and re.search(r"\bShellExecution\b", text)
    ):
        findings.append(_finding(
            extension_id,
            version,
            "hidden-remote-workspace-task",
            "supply-chain",
            "HIGH",
            0.9,
            "A background workspace task launches a remote GitHub commit through npx while using hidden task presentation markers.",
            [rel],
            "Review the exact remote repository and commit, require independently trusted provenance, and keep the task visible and user-approved.",
            {
                "evidence_class": "correlated",
                "correlation": "remote-github-execution-plus-hidden-workspace-task",
                "remote_source": remote_github_npx_match.group(0),
                "hidden_markers": sorted(set(hidden_workspace_task_matches)),
                "execution_surface": "ShellExecution",
            },
        ))

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
        bundle_profile = analyze_generated_bundle(text)
        if bundle_profile["strong_obfuscation"]:
            findings.append(_finding(
                extension_id,
                version,
                "executable-heavy-obfuscation",
                "code",
                "MEDIUM",
                0.9,
                "Executable bundle uses systematic control-flow and identifier obfuscation that materially limits static interpretation.",
                [rel],
                "Require manual review or a trusted reproducible source-to-artifact comparison before approval.",
                {
                    "evidence_class": "posture",
                    "analysis": "bounded-static-bundle-profile",
                    "scope": "entrypoint" if is_entrypoint else "secondary-generated",
                    "obfuscation_indicators": bundle_profile["obfuscation_indicators"],
                    "metrics": bundle_profile["metrics"],
                },
            ))
        if bundle_profile["harvesting_exfiltration"]:
            findings.append(_finding(
                extension_id,
                version,
                "obfuscated-credential-harvesting-exfiltration",
                "credential-access",
                "HIGH",
                0.94,
                "An obfuscated executable bundle contains a multi-family credential collector and outbound payload path.",
                [rel],
                "Prevent execution and investigate the credential targets, collection APIs, and outbound destination.",
                {
                    "evidence_class": "correlated",
                    "correlation": "obfuscation-resistant-semantic-feature-chain",
                    "credential_families": bundle_profile["credential_families"],
                    "collection_signals": bundle_profile["collection_signals"],
                    "exfiltration_signals": bundle_profile["exfiltration_signals"],
                    "obfuscation_indicators": bundle_profile["obfuscation_indicators"],
                    "metrics": bundle_profile["metrics"],
                },
            ))
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
    # Credential text, a file read, and a network call in one source file are
    # common in legitimate authenticated clients and bundled agent tools. A
    # verdict-driving exfiltration chain requires the value itself to reach the
    # network sink; proximity remains a separate exposure note below.
    direct_credential_network_flow = bool(identifier_credential_flow) or _has_direct_credential_network_flow(text, secret_regex)
    if secret_refs and has_file_read and has_network and direct_credential_network_flow:
        findings.append(_finding(
            extension_id,
            version,
            "credential-exfiltration-chain",
            "credential-access",
            "HIGH",
            0.94,
            "A credential-file value reaches an outbound network write through a bounded local data flow.",
            [rel],
            "Verify the exact credential source, destination, and user-authorized purpose before allowing the extension.",
            {"evidence_class": "correlated", "correlation": "proven-local-value-flow"},
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
    if (
        has_network
        and remote_broker_re.search(text)
        and token_material_re.search(text)
        and bearer_forward_re.search(text)
    ):
        findings.append(_finding(
            extension_id,
            version,
            "remote-credential-broker",
            "cross-extension-exposure",
            "HIGH",
            0.84,
            "Code appears to obtain or forward bearer tokens through a separately configured remote token broker.",
            [rel],
            "Verify endpoint ownership, token scope, retention, and user disclosure. This is a trust-boundary review signal, not proof of exfiltration or malicious intent.",
            {
                "evidence_class": "exposure",
                "correlation": "same-file-semantic-chain",
                "signals": ["remote-token-endpoint", "token-material", "bearer-forwarding", "network-sink"],
            },
        ))
    if (
        has_content_download
        and any(item.rule_id == "process-execution" and rel in item.file_refs for item in findings)
        and _has_download_execute_chain(text, process_exec_re)
    ):
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
    if (
        has_download
        and _ARCHIVE_EXTRACT_RE.search(text)
        and _DYNAMIC_MODULE_LOAD_RE.search(text)
        and not has_integrity_verification
        and not _is_generated_code_blob(rel, text)
        and _features_nearby(text, [DOWNLOAD_RE, _ARCHIVE_EXTRACT_RE, _DYNAMIC_MODULE_LOAD_RE])
    ):
        findings.append(_finding(
            extension_id,
            version,
            "supply-chain-dropper-chain",
            "supply-chain",
            "HIGH",
            0.84,
            "Code downloads remote content, extracts an archive, and dynamically loads code from a computed path without visible integrity verification.",
            [rel],
            "Require an immutable pinned source, checksum or signature verification, and a documented reason for loading downloaded code into the extension runtime.",
            {
                "evidence_class": "correlated",
                "correlation": "same-file-semantic-chain",
                "source": "remote-download",
                "transform": "archive-extraction",
                "sink": "dynamic-module-load",
            },
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

# Supply-chain dropper chain legs. The archive leg requires an actual extraction
# API, and the load leg requires either a computed (non-literal) require/import
# argument or an explicit bundler-escape loader. Plain `require('literal')` must
# not qualify: every CommonJS file contains it.
_ARCHIVE_EXTRACT_RE = re.compile(
    r"(?:\bextractAllTo(?:Async)?\s*\(|\bextractEntryTo\s*\(|\btar\.(?:x|extract)\b|"
    r"\bunzipper\.\w+|\bdecompress\s*\(|\bzlib\.(?:gunzip|gunzipSync|inflate|inflateSync|brotliDecompress)\b|"
    r"new\s+AdmZip\b|\bloadAsync\s*\()",
)
_DYNAMIC_MODULE_LOAD_RE = re.compile(
    r"(?:\b__non_webpack_require__\s*\(|\bcreateRequire\s*\(|\bModule\._load\s*\(|\bprocess\.dlopen\s*\(|"
    r"\brequire\s*\(\s*(?:path\.|`[^`]*\$\{|[A-Za-z_$][\w$]*\s*[+.\[])|"
    r"\bimport\s*\(\s*(?:path\.|`[^`]*\$\{|[A-Za-z_$][\w$]*\s*[+.\[]))",
)

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

# A request API is not automatically a download. Connectivity probes and
# proxy negotiation commonly use ``http[s].request`` with HEAD/CONNECT and may
# sit next to legitimate local ``execSync`` calls. Only treat content-oriented
# requests as the download leg of the download-and-execute chain; the broader
# DOWNLOAD_RE remains available for lower-level updater/install correlation.
#
# Do not match ``curl``/``wget`` as free text. Extensions often show a
# user-copied installation command in a notification or README; that is not
# the extension executing a downloader. Those commands are handled separately
# only when they are the literal command of a child-process invocation.
_CONTENT_DOWNLOAD_RE = re.compile(
    r"(?:\bfetch\s*\(|\bhttps?\.get\s*\(|\baxios\.get\s*\()",
    re.I,
)
_REQUEST_CALL_RE = re.compile(r"\bhttps?\.request\s*\(", re.I)
_REQUEST_METHOD_RE = re.compile(r"\bmethod\s*:\s*['\"]([A-Za-z]+)['\"]", re.I)
_DOWNLOADER_PROCESS_RE = re.compile(
    r"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(\s*['\"](?:curl|wget)(?:['\"]|\s)",
    re.I,
)
_DIRECT_DOWNLOAD_EXEC_RE = re.compile(
    r"\b(?:exec|execSync)\s*\(\s*['\"][^'\"]{0,500}\b(?:curl|wget)\b[^'\"]*\|\s*(?:ba)?sh\b",
    re.I,
)


def _content_download_offsets(text: str) -> list[int]:
    offsets: list[int] = []
    for match in _CONTENT_DOWNLOAD_RE.finditer(text):
        # fetch() is frequently used for POST telemetry or health checks. An
        # explicit non-GET method is not a content download leg.
        if match.group(0).lower().startswith("fetch"):
            window = text[match.start(): match.start() + 1200]
            method = _REQUEST_METHOD_RE.search(window)
            if method is not None and method.group(1).upper() != "GET":
                continue
        offsets.append(match.start())
    for match in _REQUEST_CALL_RE.finditer(text):
        # Bound the lookahead so a later unrelated object cannot relabel a
        # connectivity request. An omitted method is the Node default GET.
        window = text[match.start(): match.start() + 1200]
        method = _REQUEST_METHOD_RE.search(window)
        if method is None or method.group(1).upper() == "GET":
            offsets.append(match.start())
    return offsets


def _has_content_download(text: str) -> bool:
    return bool(_content_download_offsets(text) or _DOWNLOADER_PROCESS_RE.search(text))


def _call_end(text: str, opening_parenthesis: int) -> int | None:
    """Return the matching close parenthesis for a bounded source call."""
    depth = 0
    quote = ""
    escaped = False
    for index in range(opening_parenthesis, len(text)):
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
                return index
    return None


def _has_download_execute_chain(text: str, process_exec_re: re.Pattern[str]) -> bool:
    """Require an actual downloader leg to be near a distinct process sink.

    This intentionally does not treat a POST fetch, a health check, or a
    user-facing ``curl | bash`` string as a download-and-execute chain. The
    standalone rule remains review-only, but its evidence still needs to be
    specific enough to be useful to an analyst.
    """
    process_matches = list(process_exec_re.finditer(text))
    if not process_matches:
        return False
    window_chars = max(45 * 72, 240)
    for anchor in _content_download_offsets(text):
        opening_parenthesis = text.find("(", anchor)
        call_end = _call_end(text, opening_parenthesis) if opening_parenthesis >= 0 else None
        for process in process_matches:
            if process.start() < anchor or process.start() > anchor + window_chars:
                continue
            # The strongest shape is a process sink in the request callback,
            # e.g. https.get(url, response => execFile(...)).
            if call_end is not None and process.start() <= call_end:
                return True
            # A promise/response handoff is also meaningful, unlike a health
            # check followed by an unrelated process call elsewhere in the
            # file. Keep this list deliberately narrow and explainable.
            handoff = text[call_end + 1 if call_end is not None else anchor: process.start()]
            if re.search(r"\b(?:then|arrayBuffer|text|json|body|pipe|writeFile|createWriteStream)\b", handoff, re.I):
                return True
    direct = _DIRECT_DOWNLOAD_EXEC_RE.search(text)
    if direct is not None:
        return True
    for downloader in _DOWNLOADER_PROCESS_RE.finditer(text):
        if any(
            process.start() != downloader.start()
            and abs(downloader.start() - process.start()) <= window_chars
            for process in process_matches
        ):
            return True
    return False

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
_CHILD_PROCESS_NAMESPACE_RE = re.compile(
    r"(?:const|let|var)\s+(?P<alias>[A-Za-z_$][\w$]*)\s*=\s*"
    r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)",
    re.I,
)


def _aliased_process_execution(text: str) -> tuple[re.Pattern[str] | None, set[str]]:
    """Resolve emitted and source-level child_process aliases.

    TypeScript/CommonJS output commonly turns an imported exec into a
    namespace require followed by (0, child_process_1.exec)(command).
    That call is semantically the same process sink as
    require('child_process').exec(command); treating the generated form as
    ordinary property access creates a real false negative. The namespace must
    first be proven to come from child_process, and only an actual call shape
    is accepted so property reads remain non-executable context.
    """
    aliases: dict[str, str] = {}
    namespace_aliases: set[str] = set()
    for match in _CHILD_PROCESS_DESTRUCTURE_RE.finditer(text):
        bindings = str(match.group("bindings") or match.group("imports") or "")
        for binding in bindings.split(","):
            parts = re.split(r"\s*(?::|\bas\b)\s*", binding.strip(), maxsplit=1, flags=re.I)
            method = parts[0].strip()
            alias = parts[1].strip() if len(parts) == 2 else method
            if method in _CHILD_PROCESS_METHODS and re.fullmatch(r"[A-Za-z_$][\w$]*", alias):
                aliases[alias] = method
    namespace_aliases.update(match.group("alias") for match in _CHILD_PROCESS_NAMESPACE_RE.finditer(text))

    patterns: list[str] = []
    called_methods: set[str] = set()
    # A generated bundle can contain dozens of transpiler aliases. Searching the
    # whole source once per alias and once per method made this helper quadratic
    # in practice (and could turn a normal multi-megabyte extension into a
    # multi-minute scan). One combined pass preserves the same call-only
    # semantics without repeatedly rescanning the bundle.
    called: dict[str, str] = {}
    if aliases:
        alias_pattern = "|".join(re.escape(alias) for alias in sorted(aliases, key=len, reverse=True))
        for match in re.finditer(rf"\b(?P<alias>{alias_pattern})\s*\(", text):
            alias = match.group("alias")
            called[alias] = aliases[alias]
    if called:
        patterns.append(r"\b(?:" + "|".join(re.escape(alias) for alias in sorted(called, key=len, reverse=True)) + r")\s*\(")
        called_methods.update(called.values())

    if namespace_aliases:
        namespace_pattern = "|".join(
            re.escape(namespace) for namespace in sorted(namespace_aliases, key=len, reverse=True)
        )
        method_pattern = "|".join(re.escape(method) for method in sorted(_CHILD_PROCESS_METHODS))
        namespace_calls = re.compile(
            rf"(?:\b(?P<direct_namespace>{namespace_pattern})\s*\.\s*(?P<direct_method>{method_pattern})\s*\(|"
            rf"\(\s*0\s*,\s*(?P<wrapped_namespace>{namespace_pattern})\s*\.\s*(?P<wrapped_method>{method_pattern})\s*\)\s*\()"
        )
        namespace_methods: dict[str, set[str]] = {namespace: set() for namespace in namespace_aliases}
        for match in namespace_calls.finditer(text):
            namespace = match.group("direct_namespace") or match.group("wrapped_namespace")
            method = match.group("direct_method") or match.group("wrapped_method")
            if namespace and method:
                namespace_methods[namespace].add(method)

    for namespace in sorted(namespace_aliases, key=len, reverse=True):
        methods = sorted(namespace_methods.get(namespace, set()))
        if not methods:
            continue
        method_pattern = "|".join(re.escape(method) for method in methods)
        patterns.append(
            rf"(?:\b{re.escape(namespace)}\s*\.\s*(?:{method_pattern})\s*\(|"
            rf"\(\s*0\s*,\s*{re.escape(namespace)}\s*\.\s*(?:{method_pattern})\s*\)\s*\()"
        )
        called_methods.update(methods)

    if not patterns:
        return None, set()
    return re.compile("(?:" + "|".join(patterns) + ")"), called_methods

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
        r"(?:getConfiguration\s*\([^)]{0,500}\)\s*\.\s*get|WorkspaceConfiguration\s*\.\s*get|config\s*\.\s*get)\s*\((?P<args>[^;\n]{0,500})",
        "WorkspaceConfiguration",
    )
    sensitive_config_updates = _find_sensitive_api_text(
        text,
        r"(?:getConfiguration\s*\([^)]{0,500}\)\s*\.\s*update|WorkspaceConfiguration\s*\.\s*update|config\s*\.\s*update)\s*\((?P<args>[^;\n]{0,500})",
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
    for match in re.finditer(pattern, text, re.I):
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


def _has_environment_data_network_flow(text: str) -> dict[str, Any] | None:
    """Detect whole-environment collection reaching a local network sink.

    ``process.env`` is common in build tooling and selected environment values
    are normal telemetry or configuration. The high-specificity case is a full
    environment object (or a serialization of it) that is then passed to an
    outbound request. Keep this bounded to local assignments and request
    arguments so unrelated environment reads and network clients stay clean.
    """
    whole_environment = re.compile(r"\bprocess\.env\b(?!\s*\.)", re.I)
    assignment = re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,1400})"
    )
    for match in assignment.finditer(text):
        expression = match.group(2)
        if not whole_environment.search(expression):
            continue
        variable = match.group(1)
        tail_start = match.end()
        tail = text[tail_start:min(len(text), tail_start + 4000)]
        sink = NETWORK_SINK_RE.search(tail)
        if not sink:
            continue
        sink_tail = tail[sink.start():min(len(tail), sink.start() + 1800)]
        variable_ref = rf"\b{re.escape(variable)}\b"
        if not re.search(
            rf"(?:"
            rf"(?:body|data|payload|params|query|searchParams)\s*:\s*(?:JSON\.stringify\s*\(\s*|encodeURIComponent\s*\(\s*)?{variable_ref}"
            rf"|(?:end|write|send|post)\s*\(\s*(?:JSON\.stringify\s*\(\s*)?{variable_ref}"
            rf"|(?:JSON\.stringify|encodeURIComponent)\s*\(\s*{variable_ref}"
            rf"|(?:[?&][^;\n]{{0,120}}\+\s*|\+\s*){variable_ref}"
            rf")",
            sink_tail,
            re.I,
        ):
            continue
        return {
            "correlation": "same-variable-local-flow",
            "collection": _truncate_evidence_text(expression),
            "transfer": _truncate_evidence_text(sink_tail),
            "sink": "network-request",
        }

    # Also catch an inline request body/query, while keeping the window tight
    # enough not to turn a file-wide process.env + fetch co-occurrence into a
    # verdict-driving finding.
    for sink in NETWORK_SINK_RE.finditer(text):
        start = max(0, sink.start() - 800)
        end = min(len(text), sink.start() + 1600)
        context = text[start:end]
        collection = whole_environment.search(context)
        if not collection:
            continue
        if not re.search(
            r"(?:"
            r"(?:body|data|payload|params|query|searchParams)\s*:\s*(?:JSON\.stringify\s*\(\s*|encodeURIComponent\s*\(\s*)?\bprocess\.env\b(?!\s*\.)"
            r"|(?:end|write|send|post)\s*\(\s*(?:JSON\.stringify\s*\(\s*)?\bprocess\.env\b(?!\s*\.)"
            r"|(?:JSON\.stringify|encodeURIComponent)\s*\(\s*\bprocess\.env\b(?!\s*\.)"
            r"|(?:[?&][^;\n]{0,120}\+\s*|\+\s*)\bprocess\.env\b(?!\s*\.)"
            r")",
            context,
            re.I,
        ):
            continue
        return {
            "correlation": "inline-environment-to-network-flow",
            "collection": _truncate_evidence_text(collection.group(0)),
            "transfer": _truncate_evidence_text(context),
            "sink": "network-request",
        }
    return None


def _has_systematic_credential_harvesting_exfiltration(
    text: str,
    secret_refs: list[tuple[str, str]],
) -> bool:
    """Recognize a high-specificity, cross-function credential theft chain.

    This is intentionally stricter than file-wide source/sink co-occurrence.
    Every leg represents attacker behavior seen in credential harvesters, while
    the family-count threshold keeps normal credential providers contextual.
    """
    if len({secret_id for secret_id, _ in secret_refs}) < 3:
        return False
    collection_root = re.search(r"\b(?:os\.)?homedir\s*\(|\buserInfo\s*\(", text)
    enumerates_files = re.search(r"\b(?:fs\.)?(?:readdir|readdirSync)\s*\(", text)
    reads_files = FILE_READ_RE.search(text)
    harvesting_model = re.search(
        r"\b(?:phrases|passwords|apiKeys|awsKeys|privateKeys|vaults|wallets|mnemonic|seedPhrase)s?\b",
        text,
        re.I,
    )
    serializes = re.search(r"\b(?:JSON\.stringify|Buffer\.from)\s*\(", text)
    outbound_request = re.search(r"\bhttps?\.request\s*\(", text)
    outbound_write = re.search(r"\b(?:req|request)\.write\s*\(", text)
    return all((
        collection_root,
        enumerates_files,
        reads_files,
        harvesting_model,
        serializes,
        outbound_request,
        outbound_write,
    ))


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
    by_instance = {_runtime_instance_key(extension): extension for extension in extensions}
    for observation_key, items in observations.items():
        extension = by_instance.get(observation_key) or by_id.get(observation_key)
        if extension is None:
            continue
        for item in _aggregate_sandbox_observations(items):
            if not isinstance(item, dict):
                continue
            finding = _sandbox_observation_finding(extension, item)
            if finding is None:
                continue
            extension.findings.append(finding)
            unexpected = _runtime_unexpected_capability_finding(extension, item)
            if unexpected is not None:
                extension.findings.append(unexpected)
        (
            extension.verdict,
            extension.verdict_reason,
            extension.malware_authority,
            extension.severity,
            extension.malware_score,
            extension.risk_score,
            extension.score_details,
        ) = _classify_findings(extension.findings)


def _runtime_unexpected_capability_finding(
    extension: ExtensionReport,
    item: dict[str, Any],
) -> Finding | None:
    """Escalate runtime process/network behavior hidden from static analysis.

    Filesystem writes are intentionally excluded: caches and generated state
    are normal runtime behavior. A process or network observation that has no
    corresponding static capability is materially different, especially for a
    theme or other low-power package, and deserves review rather than being
    silently treated as an ordinary capability note.
    """
    kind = str(item.get("kind") or item.get("type") or "").strip()
    runtime_capability = {
        "process_exec": "process_execution",
        "network_attempt": "network",
        "unexpected_network": "network",
    }.get(kind)
    if not runtime_capability:
        return None
    # NSS, systemd user lookup, and syslog commonly use Unix-domain sockets.
    # The syscall tracer reports these as connect/network attempts, but they
    # are local host services rather than external network access. Do not turn
    # ordinary language-server startup into a hidden-network finding; retain
    # the low-severity runtime observation itself for transparency.
    if runtime_capability == "network":
        destination_samples = item.get("destination_samples")
        if isinstance(destination_samples, list) and destination_samples and all(
            isinstance(destination, str)
            and (destination.startswith("/") or destination.startswith("unix:"))
            for destination in destination_samples
        ):
            return None
    declared = {
        str(capability.get("id") or "")
        for capability in extension.capabilities
        if isinstance(capability, dict) and capability.get("id")
    }
    if runtime_capability in declared:
        return None
    evidence = {
        "evidence_class": "observed",
        "runtime_kind": kind,
        "capability": runtime_capability,
        "declared_capabilities": sorted(declared),
        "observation_count": int(item.get("observation_count") or 1),
    }
    if item.get("path_samples"):
        evidence["path_samples"] = list(item["path_samples"])
    if item.get("destination_samples"):
        evidence["destination_samples"] = list(item["destination_samples"])
    if item.get("command_samples"):
        evidence["command_samples"] = list(item["command_samples"])
    return _finding(
        extension.extension_id,
        extension.version,
        "observed-unexpected-capability",
        "dynamic-sandbox",
        "HIGH",
        0.86,
        f"Sandbox observed {runtime_capability.replace('_', ' ')} that static analysis did not declare.",
        [],
        "Review the exact runtime trace and package declaration; hidden process or network behavior is not expected for this artifact.",
        evidence,
        evidence_type="dynamic",
    )


_AGGREGATED_RUNTIME_OBSERVATIONS = frozenset({
    # These events prove that a capability was exercised, but repeated events
    # are not separate security incidents. Keep one finding and preserve a
    # bounded sample plus the exact count in its evidence.
    "secret_read",
    "secret_exfil",
    "canary_exposed",
    "download_execute",
    "persistence",
    "destructive",
    "network_attempt",
    "unexpected_network",
    "process_exec",
    "filesystem_write",
    "runtime_lifecycle_error",
    "runtime_entrypoint_error",
})
_RUNTIME_SAMPLE_FIELDS = ("path", "command", "destination", "api", "script", "phase")
_RUNTIME_SAMPLE_LIMIT = 25


def _aggregate_sandbox_observations(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse repeated runtime events without discarding their evidence.

    A language server can write hundreds of cache files or make several
    connection attempts during one activation. Rendering each syscall as a
    separate finding is noisy and makes capability evidence look like an
    incident count. High-specificity observations remain visible, but each
    behavior is represented once with ``observation_count`` and bounded
    samples for investigation.
    """
    grouped: dict[str, dict[str, Any]] = {}
    order: list[dict[str, Any]] = []
    for raw in items:
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind") or raw.get("type") or raw.get("rule_id") or "").strip()
        if kind not in _AGGREGATED_RUNTIME_OBSERVATIONS:
            order.append(dict(raw))
            continue
        aggregate = grouped.get(kind)
        if aggregate is None:
            aggregate = dict(raw)
            aggregate["observation_count"] = 0
            for field in _RUNTIME_SAMPLE_FIELDS:
                if raw.get(field) not in (None, ""):
                    aggregate[f"{field}_samples"] = []
            grouped[kind] = aggregate
            order.append(aggregate)
        try:
            raw_count = max(1, int(raw.get("observation_count") or 1))
        except (TypeError, ValueError):
            raw_count = 1
        aggregate["observation_count"] = int(aggregate.get("observation_count") or 0) + raw_count
        for field in _RUNTIME_SAMPLE_FIELDS:
            value = raw.get(field)
            if value in (None, ""):
                continue
            key = f"{field}_samples"
            samples = aggregate.setdefault(key, [])
            if value not in samples and len(samples) < _RUNTIME_SAMPLE_LIMIT:
                samples.append(value)
    return order


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
        raw = Path(raw_path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Configured threat feed could not be read: {raw_path}: {exc}") from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Configured threat feed is not valid JSON: {raw_path}: {exc}") from exc
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
    if not out:
        raise ValueError(f"Configured threat feed contains no valid extension entries: {raw_path}")
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
            threat_classification = str(entry.get("threat_classification") or "").strip().lower()
            confirmed_malware = threat_classification == "malicious"
            evidence = dict(entry)
            evidence.update({
                "evidence_class": "confirmed" if confirmed_malware else "vulnerability",
                "snapshot_version": str(bundle.get("snapshot_version") or "unknown"),
                "snapshot_sha256": str(bundle.get("sha256") or ""),
                "exact": True,
            })
            rule_id = "known-malicious-extension" if confirmed_malware else "known-vulnerable-extension"
            extension.findings.append(_finding(
                extension.extension_id,
                extension.version,
                rule_id,
                "confirmed-intelligence" if confirmed_malware else "vulnerability",
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
        "canary_exposed": ("runtime-canary-exposed", "INFO", 0.35, "Sandbox observed the synthetic canary in process output; this does not establish external transfer."),
        "download_execute": ("observed-download-execute", "HIGH", 0.86, "Sandbox observed downloaded content being executed or loaded."),
        "persistence": ("observed-persistence", "HIGH", 0.84, "Sandbox observed persistence or autorun behavior."),
        "destructive": ("observed-destructive-behavior", "HIGH", 0.88, "Sandbox observed destructive file behavior."),
        "network_attempt": ("runtime-network-attempt", "INFO", 0.35, "Sandbox observed an attempted network request; isolation prevented the request from completing."),
        "unexpected_network": ("runtime-network-attempt", "INFO", 0.35, "Sandbox observed an attempted network request; isolation prevented the request from completing."),
        "process_exec": ("runtime-process-execution", "INFO", 0.35, "Sandbox observed process execution; this confirms capability, not malicious intent."),
        "filesystem_write": ("runtime-filesystem-write", "INFO", 0.3, "Sandbox observed a filesystem write; this confirms capability, not malicious intent."),
        "runtime_lifecycle_error": ("runtime-lifecycle-error", "INFO", 0.4, "A lifecycle script exited unsuccessfully; activation coverage was still attempted."),
        "runtime_entrypoint_error": ("runtime-entrypoint-error", "INFO", 0.4, "The controlled entrypoint exited unsuccessfully after emitting authenticated runtime evidence; review the exit context alongside the observed behavior."),
    }
    if kind == "runtime_timeout":
        rule_id, severity, confidence, summary = (
            "sandbox-runtime-timeout",
            "INFO",
            0.4,
            "Sandbox action timed out; runtime coverage is incomplete.",
        )
        evidence_class = "weak"
    elif kind == "sandbox_error":
        rule_id, severity, confidence, summary = (
            "sandbox-runtime-error",
            "INFO",
            0.35,
            "Sandbox runtime instrumentation could not complete; runtime coverage is incomplete.",
        )
        evidence_class = "weak"
    elif kind in mapping:
        rule_id, severity, confidence, summary = mapping[kind]
        evidence_class = "weak" if kind in {
            "network_attempt", "unexpected_network", "process_exec", "filesystem_write",
            "canary_exposed", "runtime_lifecycle_error", "runtime_entrypoint_error",
        } else "observed"
    else:
        return None
    evidence = dict(item)
    evidence["evidence_class"] = evidence_class
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
        "Review the authenticated runtime evidence. Dynamic observations are strong evidence but not authoritative malware without confirmed intelligence.",
        evidence,
        evidence_type="dynamic",
    )


def _load_sandbox_observation_bundle(path: Path | str | None = None) -> dict[str, Any]:
    raw_path = str(path or os.environ.get("IDE_SCANNER_SANDBOX_OBSERVATIONS_FILE") or "")
    if not raw_path:
        return {
            "extensions": {},
            "metadata": {
                "status": "not-requested",
                "mode": "static-only",
                "executed": False,
                "observation_count": 0,
            },
        }
    try:
        parsed = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "extensions": {},
            "metadata": {
                "status": "failed",
                "mode": "external",
                "executed": False,
                "observation_count": 0,
                "error": "sandbox observations file could not be read or parsed",
            },
        }
    metadata_source = parsed if isinstance(parsed, dict) else {}
    extension_payload = metadata_source.get("extensions") if isinstance(metadata_source.get("extensions"), dict) else parsed
    if not isinstance(extension_payload, dict):
        return {
            "extensions": {},
            "metadata": {
                "status": "failed",
                "mode": "external",
                "executed": False,
                "observation_count": 0,
                "error": "sandbox observations payload has no extensions object",
            },
        }
    out: dict[str, list[dict[str, Any]]] = {}
    for extension_id, items in extension_payload.items():
        if isinstance(extension_id, str) and isinstance(items, list):
            out[extension_id] = [item for item in items if isinstance(item, dict)]
    mode = str(metadata_source.get("mode") or "external")
    if mode == "executed":
        status = "executed"
        execution = "controlled-bubblewrap"
    elif mode == "plan-only":
        status = "planned"
        execution = "not-run"
    else:
        status = "imported"
        execution = "external"
    plan = metadata_source.get("plan") if isinstance(metadata_source.get("plan"), dict) else {}
    instrumentation = plan.get("instrumentation") if isinstance(plan.get("instrumentation"), dict) else {}
    metadata: dict[str, Any] = {
        "status": status,
        "mode": mode,
        "execution": execution,
        "executed": mode == "executed",
        "schema_version": str(metadata_source.get("schema_version") or "unknown"),
        "backend": str(plan.get("backend") or "external"),
        "observation_count": sum(len(items) for items in out.values()),
        "observed_kinds": _observation_kinds(out),
    }
    if isinstance(plan.get("resource_limits"), dict):
        metadata["resource_limits"] = dict(plan["resource_limits"])
    if isinstance(plan.get("runtime_probes"), dict):
        metadata["runtime_probes"] = dict(plan["runtime_probes"])
    if isinstance(instrumentation.get("captures"), list):
        metadata["captures"] = [str(item) for item in instrumentation["captures"]]
    external_trace = instrumentation.get("external_syscall_trace")
    if isinstance(external_trace, dict):
        trace_available = bool(
            external_trace.get("requested") is True
            and external_trace.get("available") is True
        )
        metadata["external_syscall_trace_available"] = trace_available
        metadata["external_syscall_trace"] = trace_available
    return {"extensions": out, "metadata": metadata}


def _load_sandbox_observations(path: Path | str | None = None) -> dict[str, list[dict[str, Any]]]:
    """Backward-compatible access to the extension observation map."""
    bundle = _load_sandbox_observation_bundle(path)
    return bundle["extensions"]


def _merge_dynamic_runtime_bundle(
    sandbox_bundle: dict[str, Any],
    runtime_bundle: dict[str, Any],
) -> dict[str, Any]:
    """Combine explicit external evidence with the in-process runtime pass."""
    merged_extensions = {
        key: list(value)
        for key, value in (sandbox_bundle.get("extensions") or {}).items()
        if isinstance(key, str) and isinstance(value, list)
    }
    for key, value in (runtime_bundle.get("extensions") or {}).items():
        if isinstance(key, str) and isinstance(value, list):
            merged_extensions.setdefault(key, []).extend(item for item in value if isinstance(item, dict))
    base_metadata = sandbox_bundle.get("metadata") if isinstance(sandbox_bundle.get("metadata"), dict) else {}
    runs = runtime_bundle.get("runs") if isinstance(runtime_bundle.get("runs"), list) else []
    required_ids = runtime_bundle.get("required_extension_ids") if isinstance(runtime_bundle.get("required_extension_ids"), list) else []
    base_required_ids = base_metadata.get("runtime_required_ids") if isinstance(base_metadata.get("runtime_required_ids"), list) else []
    required_instances = runtime_bundle.get("runtime_required_instances") if isinstance(runtime_bundle.get("runtime_required_instances"), list) else []
    base_required_instances = base_metadata.get("runtime_required_instances") if isinstance(base_metadata.get("runtime_required_instances"), list) else []
    metadata = dict(base_metadata)
    metadata.update({
        "status": "executed",
        "mode": "executed",
        "execution": "controlled-bubblewrap",
        "executed": True,
        "backend": "bubblewrap",
        "runtime_policy": "capability-gated-v1",
        "runtime_runs": runs,
        "runtime_required_ids": sorted({str(item) for item in [*base_required_ids, *required_ids] if str(item)}),
        "runtime_required_instances": sorted({
            str(item)
            for item in [*base_required_instances, *required_instances]
            if str(item)
        }),
        "observation_count": sum(len(value) for value in merged_extensions.values()),
        "observed_kinds": _observation_kinds(merged_extensions, runs=runs),
        "external_syscall_trace": bool(
            runtime_bundle.get("external_syscall_trace") is True
            or base_metadata.get("external_syscall_trace") is True
        ),
        "external_syscall_trace_available": bool(
            runtime_bundle.get("external_syscall_trace_available") is True
            or base_metadata.get("external_syscall_trace_available") is True
        ),
    })
    return {"extensions": merged_extensions, "metadata": metadata}


def _observation_kinds(
    observations: dict[str, list[dict[str, Any]]],
    *,
    runs: list[dict[str, Any]] | None = None,
) -> dict[str, list[str]]:
    """Expose bounded runtime event types without persisting raw paths/commands."""
    labels = {
        str(item.get("instance_id")): str(item.get("extension_id"))
        for item in (runs or [])
        if isinstance(item, dict) and item.get("instance_id") and item.get("extension_id")
    }
    result: dict[str, set[str]] = {}
    for instance_key, items in observations.items():
        if not items:
            continue
        label = labels.get(instance_key, instance_key)
        result.setdefault(label, set()).update(
            str(item.get("kind")) for item in items if item.get("kind")
        )
    return {key: sorted(values) for key, values in result.items()}


def _apply_sandbox_provider(extensions: list[ExtensionReport], bundle: dict[str, Any]) -> None:
    metadata = bundle.get("metadata") if isinstance(bundle.get("metadata"), dict) else {}
    observations = bundle.get("extensions") if isinstance(bundle.get("extensions"), dict) else {}
    runtime_runs = [
        item for item in (metadata.get("runtime_runs") or [])
        if isinstance(item, dict)
    ]
    status = str(metadata.get("status") or "not-requested")
    required_ids = {str(item).lower() for item in metadata.get("runtime_required_ids", []) if str(item)}
    required_instances = {str(item) for item in metadata.get("runtime_required_instances", []) if str(item)}
    for extension in extensions:
        instance_key = _runtime_instance_key(extension)
        items = _runtime_observations_for_report(observations, extension)
        required = (
            instance_key in required_instances
            or (not required_instances and extension.extension_id.lower() in required_ids)
        )
        provider_status = status
        execution = str(metadata.get("execution") or "not-run")
        executed = bool(metadata.get("executed"))
        runtime_run = next(
            (
                item for item in runtime_runs
                if str(item.get("instance_id") or "") == instance_key
            ),
            None,
        )
        if runtime_run is None and not required_instances:
            matching_runs = [
                item for item in runtime_runs
                if str(item.get("extension_id") or "").lower() == extension.extension_id.lower()
            ]
            if len(matching_runs) == 1:
                runtime_run = matching_runs[0]
        error_count = sum(
            1 for item in items
            if isinstance(item, dict) and str(item.get("kind") or "") in {"runtime_timeout", "sandbox_error"}
        ) if isinstance(items, list) else 0
        if metadata.get("runtime_policy") == "capability-gated-v1" and not required:
            provider_status = "not-applicable"
            execution = "policy-gated"
            executed = False
        elif required:
            # Aggregate metadata and observations are not enough to establish
            # coverage. Require the exact per-artifact run receipt as well, so
            # a truncated/malformed runtime bundle cannot turn into a green
            # provider merely because it contains no explicit sandbox_error.
            run_status = str(runtime_run.get("status") or "") if runtime_run else "missing"
            run_trace = bool(runtime_run and runtime_run.get("external_syscall_trace") is True)
            if provider_status in {"executed", "completed"} and run_status == "completed" and run_trace:
                provider_status = "completed"
            else:
                provider_status = "failed"
                if not error_count:
                    error_count = 1
        if required and runtime_run is not None and str(runtime_run.get("status") or "") != "completed":
            error_count = max(error_count, 1)
        if required and runtime_run is None:
            error_count = max(error_count, 1)
        if required and error_count:
            provider_status = "failed"
        provider = {
            "provider": "dynamic_sandbox",
            "status": provider_status,
            "mode": str(metadata.get("mode") or "static-only"),
            "execution": execution,
            "executed": executed,
            "observation_count": len(items) if isinstance(items, list) else 0,
            "error_count": error_count,
            "required": required,
            "policy": str(metadata.get("runtime_policy") or "external-evidence"),
            # A runtime request and a host-level strace binary are not enough
            # to prove evidence. Required artifacts only receive this bit
            # when the parent-owned trace was available and the run produced
            # no runtime failure. Non-executable packages are explicitly
            # not-applicable and therefore do not claim a trace.
            "external_syscall_trace": bool(
                required
                and metadata.get("external_syscall_trace") is True
                and runtime_run is not None
                and runtime_run.get("status") == "completed"
                and runtime_run.get("external_syscall_trace") is True
                and error_count == 0
            ),
            "external_syscall_trace_available": bool(
                metadata.get("external_syscall_trace_available") is True
            ),
            "runtime_run_status": str(runtime_run.get("status") or "missing") if runtime_run else "missing",
        }
        extension.analysis_coverage.setdefault("providers", {})["dynamic_sandbox"] = provider
        # Runtime coverage is attached after the static provider pass has
        # already been finalized. Recompute the aggregate completeness here so
        # a failed required sandbox run cannot leave a clean executable
        # extension in the approval path simply because static coverage was
        # complete. This is deliberately fail-closed: required dynamic
        # evidence is either completed with an external trace or the artifact
        # remains incomplete and cannot be allowed.
        _finalize_analysis_coverage(extension.analysis_coverage)
        if required:
            declared = {
                str(capability.get("id") or "")
                for capability in extension.capabilities
                if isinstance(capability, dict) and capability.get("id")
            }
            observed_capabilities = sorted({
                capability
                for item in items
                if isinstance(item, dict)
                for capability in (
                    {
                        "process_exec": "process_execution",
                        "network_attempt": "network",
                        "unexpected_network": "network",
                    }.get(str(item.get("kind") or "")),
                )
                if capability
            })
            undeclared = sorted(set(observed_capabilities) - declared)
            extension.capability_assessment = {
                "behavioral_verification": {
                    "status": "complete" if provider_status == "completed" else "failed",
                    "matches_declaration": provider_status == "completed" and not undeclared,
                    "observed_capabilities": observed_capabilities,
                    "undeclared_capabilities": undeclared,
                    "observation_count": len(items) if isinstance(items, list) else 0,
                    "provider": "dynamic_sandbox",
                }
            }


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
    by_analysis_status: dict[str, int] = {}
    max_score = 0
    max_malware_score = 0
    max_risk_score = 0
    for extension in extensions:
        analysis_status = str(extension.analysis_status or "incomplete")
        by_analysis_status[analysis_status] = by_analysis_status.get(analysis_status, 0) + 1
        if analysis_status == "complete" and extension.decision != "incomplete":
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
        "by_analysis_status": by_analysis_status,
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
        "scanner_build": scanner_build(),
        "ruleset_version": RULESET_VERSION,
        "policy_version": POLICY_VERSION,
        "privacy_mode": (
            "local-metadata-static-features-plus-controlled-runtime"
            if str((intelligence or {}).get("dynamic_sandbox", {}).get("status") or "") in {"executed", "imported"}
            else "local-metadata-and-static-features"
        ),
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
    by_analysis_status = summary.get("by_analysis_status", {})
    notes = [
        f"Scanned {summary.get('total_extensions', 0)} extension(s): "
        f"{by_verdict.get('malicious', 0)} malicious, "
        f"{by_verdict.get('suspicious', 0)} suspicious, "
        f"{by_verdict.get('review', 0)} review, "
        f"{by_verdict.get('clean', 0)} clean, "
        f"{sum(count for status, count in by_analysis_status.items() if status != 'complete')} incomplete."
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
    blocking_rule_ids = _preventive_blocking_rule_ids(extension.findings)
    vulnerability_blocks = {
        finding.rule_id for finding in extension.findings
        if finding_actionability(finding) == "block" and _finding_evidence_class(finding) == "vulnerability"
    }
    # Analysis completeness and enforcement are independent invariants.
    # Actionable block evidence remains enforceable even if another provider
    # fails; an incomplete scan must never become an approval.
    if extension.verdict == "malicious":
        extension.decision = "block"
        extension.decision_reason = "Confirmed malicious intelligence or an exact known-bad artifact matched."
        return
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
    if incomplete:
        extension.decision = "incomplete"
        extension.decision_reason = str(extension.artifact_inventory.get("skipped_reason") or "Executable analysis did not complete.")
        return
    contract_unexpected = _contract_unexpected_capabilities(extension)
    if contract_unexpected:
        extension.decision = "review"
        extension.decision_reason = (
            "Observed capabilities fall outside the extension's functional contract: "
            f"{', '.join(contract_unexpected[:5])}."
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


def _contract_unexpected_capabilities(extension: ExtensionReport) -> list[str]:
    """Return capabilities that contradict a known functional class.

    Capability findings are intentionally contextual in isolation. A theme that
    also exposes process, network, native, or credential powers is different:
    those powers contradict the package's declared job and should enter review
    even when static capability rules alone would otherwise be non-actionable.
    Unknown packages are not penalized by this check; they remain governed by
    their direct evidence and provenance.
    """
    classification = classify_extension(extension)
    class_id = str(classification.get("primary") or "unknown")
    if class_id == "unknown":
        return []
    profile = None
    try:
        from .capability_contracts import extension_profile

        profile = extension_profile(extension.extension_id)
    except (ImportError, TypeError):
        profile = None
    expected = expected_capabilities(profile, class_id)
    if not expected:
        return []
    observed = {
        str(item.get("id") or "")
        for item in extension.capabilities
        if isinstance(item, dict) and item.get("id")
    }
    forbidden = {
        str(item)
        for item in class_contract(class_id).get("forbidden", [])
        if str(item)
    }
    # The positive capability lists are explanatory baselines, not complete
    # allowlists: language tools often use network/filesystem helpers that are
    # absent from a compact profile. Only an explicit forbidden capability is
    # strong enough to change the decision at this layer.
    return sorted(observed & forbidden)


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
    a preventive block only when the scanner establishes a direct credential
    dataflow or another independent abuse chain. A credential prompt is an
    exposure signal, not proof that the entered value reaches the downloaded
    process. Confirmed intelligence is handled separately by verdict.
    """
    rule_ids = {finding.rule_id for finding in findings}
    blocking = rule_ids & (BLOCKING_CORRELATED_RULES | BLOCKING_OBSERVED_RULES)
    # A filename/token reference is only exposure evidence. It is deliberately
    # excluded here: a downloaded tool plus a nearby `.env` or credential label
    # is common in developer tooling and does not prove that the secret is used.
    # A credential prompt remains contextual until a source-to-sink rule proves
    # that the value reaches a file, network, or process sink.
    credential_signal = bool(rule_ids & DOWNLOAD_EXECUTE_CREDENTIAL_SIGNALS)
    if "download-and-execute" in rule_ids and credential_signal:
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
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="ide-scanner-inventory-", suffix=".json") as targets:
        json.dump([file.relative_to(path).as_posix() for file in files], targets)
        targets.flush()
        command = [
            sys.executable, "-m", "ide_scanner.providers.artifact_worker",
            "--operation", "inventory", "--root", str(path.resolve()), "--targets", targets.name,
        ]
        environment = _worker_environment()
        try:
            completed = run_bounded_process(command, timeout=300, memory_limit_mb=768, env=environment)
        except subprocess.TimeoutExpired as exc:
            raise ValueError("artifact inventory worker timed out") from exc
    payload = _artifact_worker_payload(completed, "artifact inventory")
    inventory = payload.get("inventory")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("_all_file_hashes"), list):
        raise ValueError("artifact inventory worker omitted inventory metadata")
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
    except OSError as exc:
        raise ValueError(f"Configured known-bad hash feed could not be read: {raw_path}: {exc}") from exc
    if not text.strip():
        raise ValueError(f"Configured known-bad hash feed is empty: {raw_path}")

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        hashes = _load_line_based_hashes(text, raw_path)
    else:
        hashes = _load_json_hashes(parsed, raw_path)
    if not hashes:
        raise ValueError(f"Configured known-bad hash feed contains no valid SHA-256 hashes: {raw_path}")
    return hashes


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
    """Extract an untrusted VSIX in a time- and memory-bounded subprocess."""
    command = [
        sys.executable,
        "-m",
        "ide_scanner.providers.artifact_worker",
        "--vsix",
        str(vsix_path.resolve()),
        "--destination",
        str(destination.resolve()),
    ]
    try:
        completed = run_bounded_process(command, timeout=180, memory_limit_mb=512, env=_worker_environment())
    except subprocess.TimeoutExpired as exc:
        raise ValueError("VSIX extraction worker timed out") from exc
    payload = _artifact_worker_payload(completed, "VSIX extraction")
    anomalies = payload.get("anomalies")
    if not isinstance(anomalies, dict):
        raise ValueError("VSIX extraction worker omitted anomaly metadata")
    return anomalies


def _worker_environment() -> dict[str, str]:
    environment = safe_child_environment()
    source_root = str(Path(__file__).resolve().parent.parent)
    environment["PYTHONPATH"] = os.pathsep.join(
        item for item in (source_root, environment.get("PYTHONPATH", "")) if item
    )
    return environment


def _artifact_worker_payload(completed: subprocess.CompletedProcess[str], operation: str) -> dict[str, Any]:
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        detail = completed.stderr.strip()[:500]
        raise ValueError(f"{operation} worker returned invalid output: {detail}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{operation} worker returned invalid output")
    if completed.returncode != 0 or payload.get("status") != "complete":
        detail = str(payload.get("error") or completed.stderr or "unknown worker failure")[:500]
        raise ValueError(f"{operation} worker failed: {detail}")
    if payload.get("schema_version") != "1":
        raise ValueError(f"{operation} worker returned an unsupported schema")
    return payload


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


def _enforce_extension_resource_budget(path: Path) -> None:
    """Reject oversized local artifacts before expensive analysis begins.

    The caller isolates this exception into an explicit incomplete report. We
    intentionally do not truncate a package and call it analyzed: partial
    executable coverage would make a clean result unsafe to publish.
    """
    if not path.is_dir():
        return
    total_bytes = 0
    file_count = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for filename in filenames:
            candidate = Path(dirpath, filename)
            if candidate.is_symlink():
                continue
            try:
                size = candidate.stat().st_size
            except OSError as exc:
                raise ValueError(f"Artifact resource budget could not stat {candidate}: {exc}") from exc
            file_count += 1
            total_bytes += size
            if file_count > MAX_EXTENSION_FILES:
                raise ValueError(
                    f"Artifact exceeds scan resource budget: {file_count} files > {MAX_EXTENSION_FILES}"
                )
            if total_bytes > MAX_EXTENSION_BYTES:
                raise ValueError(
                    "Artifact exceeds scan resource budget: "
                    f"{total_bytes} bytes > {MAX_EXTENSION_BYTES}"
                )
def _declared_entrypoints(manifest: dict[str, Any], path: Path) -> tuple[set[str], list[str]]:
    entrypoints: set[str] = set()
    optional_missing: list[str] = []
    main_value = manifest.get("main")
    browser_value = manifest.get("browser")
    has_main = isinstance(main_value, str) and bool(main_value.strip())
    if has_main:
        declared_main = _normalize_package_path(str(main_value))
        entrypoints.add(_resolve_node_entrypoint(path, declared_main))
    if isinstance(browser_value, str) and browser_value.strip():
        declared_browser = _normalize_package_path(browser_value)
        resolved_browser = _resolve_node_entrypoint(path, declared_browser)
        if path.joinpath(*resolved_browser.split("/")).is_file() or not has_main:
            entrypoints.add(resolved_browser)
        else:
            # VS Code's `browser` field is an alternate web target. A package
            # with a valid desktop `main` remains analyzable for desktop
            # installs even when it does not ship the optional web bundle.
            # Preserve the omission as evidence without turning it into a
            # false incomplete verdict for the artifact being scanned.
            optional_missing.append(resolved_browser)
    if not entrypoints and (path / "extension.js").is_file():
        entrypoints.add("extension.js")
    return entrypoints, optional_missing


def _normalize_package_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    # A few published VSIX manifests spell package-relative entrypoints with
    # a leading slash. Treat that spelling like the runtime harness does;
    # otherwise coverage reports a false missing entrypoint even though the
    # bytes are present inside the artifact.
    normalized = normalized.lstrip("/")
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


def _new_analysis_coverage(
    files: list[Path],
    entrypoints: set[str],
    path: Path,
    optional_missing_entrypoints: list[str] | None = None,
) -> dict[str, Any]:
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
        "optional_missing_entrypoints": sorted(set(optional_missing_entrypoints or [])),
        "executable_candidates": candidates,
        "excluded_generated_files": excluded_generated,
        "analyzed_executable_files": [],
        "read_failures": [],
        "oversized_files": [],
        "limitations": [],
        "providers": {},
        "provider_scopes": {
            "semgrep": {
                "eligible_files": [],
                "excluded_files": [
                    {"path": rel, "reason": "generated or vendored path"}
                    for rel in excluded_generated
                    if Path(rel).suffix.lower() in JS_AST_EXTS
                ],
            },
        },
    }


def _finalize_analysis_coverage(coverage: dict[str, Any]) -> None:
    candidates = set(coverage.get("executable_candidates") or [])
    analyzed = set(coverage.get("analyzed_executable_files") or [])
    missing = list(coverage.get("missing_entrypoints") or [])
    failures = list(coverage.get("read_failures") or [])
    oversized = list(coverage.get("oversized_files") or [])
    # Preserve request/worker-level limitations already attached to the
    # coverage object. Rebuilding this list from structural fields alone used
    # to erase the real reason an artifact was quarantined (for example, an
    # extension-size budget failure) and replace it with the less useful
    # generic ``scan-aborted`` manifest label.
    limitations: list[str] = list(coverage.get("limitations") or [])

    def add_limitation(value: str) -> None:
        if value and value not in limitations:
            limitations.append(value)

    manifest_validation = coverage.get("manifest_validation")
    if isinstance(manifest_validation, dict) and not manifest_validation.get("valid"):
        add_limitation(
            f"Manifest (package.json) is not trustworthy: {manifest_validation.get('status') or 'invalid'}"
        )
    if missing:
        add_limitation(f"Missing declared entrypoint(s): {', '.join(missing[:3])}")
    if failures:
        add_limitation(f"Could not read {len(failures)} executable file(s)")
    if oversized:
        add_limitation(f"Skipped {len(oversized)} executable file(s) larger than {MAX_TEXT_BYTES} bytes")
    required = candidates - set(oversized) - set(failures)
    if required - analyzed:
        add_limitation(f"Did not analyze {len(required - analyzed)} executable candidate(s)")
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
    # A scan can be finalized once during artifact analysis, before the
    # request-level providers (for example dependency intelligence) are
    # attached.  A later finalization must not preserve that provisional
    # failure after the provider has reported success; otherwise every deep
    # worker result is permanently quarantined as incomplete despite complete
    # provider evidence.
    completed_provider_limitations = {
        f"Required provider {name} did not complete"
        for name in required_providers
        if isinstance(providers.get(name), dict)
        and providers[name].get("status") == "completed"
    }
    limitations = [item for item in limitations if item not in completed_provider_limitations]
    for name in sorted(required_providers):
        provider = providers.get(name) if isinstance(providers.get(name), dict) else {}
        provider["required"] = True
        providers[name] = provider
        if provider.get("status") != "completed":
            add_limitation(f"Required provider {name} did not complete")
    completed_required_providers = sorted(
        name
        for name in required_providers
        if isinstance(providers.get(name), dict) and providers[name].get("status") == "completed"
    )
    coverage["required_providers"] = sorted(required_providers)
    coverage["completed_required_providers"] = completed_required_providers
    coverage["required_providers_complete"] = (
        len(completed_required_providers) == len(required_providers)
    )
    excluded_generated = list(coverage.get("excluded_generated_files") or [])
    coverage["skipped_generated_count"] = len(excluded_generated)
    denominator = len(candidates) + len(missing)
    if denominator:
        executable_file_coverage = round(100 * len(analyzed & candidates) / denominator)
    elif excluded_generated:
        # No analyzable entrypoint or hand-written executable file was reachable,
        # yet the artifact ships generated/minified runtime code. Reporting 100%
        # here would claim full analysis of code that was never inspected.
        executable_file_coverage = 0
        add_limitation(
            f"No analyzable entrypoint was reachable; {len(excluded_generated)} generated/minified "
            "runtime file(s) were present but not analyzed"
        )
    elif limitations:
        # A worker- or request-level failure can arrive before the scanner has
        # discovered any executable candidates. An empty denominator must not
        # turn that failed analysis into a misleading 100% coverage claim.
        executable_file_coverage = 0
    else:
        executable_file_coverage = 100
    coverage["executable_file_coverage_percent"] = executable_file_coverage
    # Compatibility alias for schema-v2 consumers. Analyzer completion is a
    # separate invariant represented by required_providers_complete and status.
    coverage["coverage_percent"] = executable_file_coverage
    coverage["limitations"] = limitations
    coverage["status"] = "complete" if not limitations else "incomplete"


def _is_ignored_static_asset(rel: str) -> bool:
    normalized = rel.replace("\\", "/").lower()
    generated_prefixes = (
        "node_modules/",
        # Documentation/demo JavaScript is shipped for the extension's
        # project website or README examples, not loaded by the IDE runtime.
        # Keep the bytes in artifact-wide inventory/YARA coverage, but do not
        # let a docs service worker or example page grant an extension a
        # runtime network/process capability. Declared entrypoints still
        # override this filter and are always analyzed.
        "docs/",
        "documentation/",
        "examples/",
        "example/",
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
        "/build/assets/",
        "/build/static/js/",
        "/node_modules/",
    )
    rooted = f"/{normalized.lstrip('/')}"
    if normalized.startswith(generated_prefixes) or any(part in rooted for part in generated_parts):
        return True
    name = Path(rel).name.lower()
    if name.endswith(".d.ts") or (
        name.startswith(("chunk-", "chunk."))
        and Path(rel).suffix.lower() in JS_AST_EXTS
    ):
        return True
    return name.endswith((
        ".chunk.js",
        ".chunk.mjs",
        ".min.js",
        ".min.mjs",
        ".bundle.js",
        ".bundle.mjs",
        ".map",
    ))


def _is_documentation_preview(rel: str) -> bool:
    path = Path(rel)
    return path.suffix.lower() in DOCUMENTATION_PREVIEW_EXTS and path.stem.lower() == "readme"


def _is_primary_readme(rel: str) -> bool:
    path = Path(rel)
    return path.parent == Path(".") and _is_documentation_preview(rel)


def _bounded_source_preview(path: Path, rel: str) -> dict[str, Any] | None:
    if path.is_symlink() or path.stat().st_size > MAX_SOURCE_PREVIEW_BYTES:
        return None
    content = _read_text(path)
    if content is None:
        return None
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_SOURCE_PREVIEW_BYTES:
        return None
    return {
        "path": rel,
        "content": content,
        "content_sha256": hashlib.sha256(encoded).hexdigest(),
        "truncated": False,
    }


def _static_provider_targets(
    files: list[Path],
    root: Path,
    coverage: dict[str, Any],
) -> dict[str, list[str]]:
    semgrep = sorted(
        str(rel)
        for rel in (
            (coverage.get("provider_scopes") or {})
            .get("semgrep", {})
            .get("eligible_files", [])
        )
        if root.joinpath(*str(rel).split("/")).is_file()
    )
    # YARA remains an artifact-wide byte scanner. Rule-specific eligibility and
    # format validation happen after a match; narrowing this list by filename would
    # create blind spots for executable bytes hidden in arbitrary containers.
    yara = [file.relative_to(root).as_posix() for file in files if not file.is_symlink()]
    return {"semgrep": semgrep, "yara": sorted(set(yara))}


def _is_generated_code_blob(rel: str, text: str) -> bool:
    normalized = rel.replace("\\", "/").lower()
    if normalized.endswith((".min.js", ".min.mjs", ".bundle.js", ".bundle.mjs", ".chunk.js", ".chunk.mjs")):
        return True
    # Webpack keeps readable line breaks in development-mode bundles, so line
    # density alone misses large generated entrypoints such as CMake Tools.
    # Their module-table markers are stable enough to suppress false import
    # edges while the AST/raw-text analyzers still inspect the bundle itself.
    if len(text) >= 1_048_576 and ("webpackBootstrap" in text[:8_192] or "__webpack_modules__" in text[:65_536]):
        return True
    newline_count = text.count("\n")
    if len(text) >= GENERATED_BLOB_BYTES:
        return True
    if len(text) >= MINIFIED_BLOB_BYTES and newline_count < 20:
        return True
    if len(text) >= MINIFIED_BLOB_BYTES and len(text) / max(1, newline_count + 1) > 500:
        return True
    return False


def _semgrep_scope_exclusion(text: str, byte_length: int | None = None) -> str | None:
    """Bound Semgrep to source-like inputs while other analyzers cover bundles.

    Semgrep's taint engine is not a byte scanner: webpack chunks and multi-MiB
    generated bundles routinely exceed its per-rule parser budget. Native
    static analysis, the bounded JavaScript AST analyzer, and YARA still inspect
    these files; the provider-specific exclusion remains explicit in coverage.
    """
    size = byte_length if byte_length is not None else len(text.encode("utf-8"))
    if size > SEMGREP_MAX_TARGET_BYTES:
        return f"exceeds Semgrep's {SEMGREP_MAX_TARGET_BYTES:,}-byte source limit"
    lines = text.count("\n") + 1
    if size >= SEMGREP_MINIFIED_SOURCE_BYTES and len(text) / lines > 500:
        return "minified/generated line density is outside Semgrep's source scope"
    return None


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
        "max_input_bytes_per_file": JS_AST_MAX_INPUT_BYTES,
        "generated_entrypoint_max_bytes": GENERATED_ENTRYPOINT_AST_MAX_BYTES,
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
        elif "generated-resource-skipped" in reasons:
            record["error"] = (
                "AST analysis skipped generated entrypoints beyond the "
                f"{GENERATED_ENTRYPOINT_AST_MAX_BYTES:,}-byte generated-code budget; "
                "bounded raw-text and YARA analysis still ran."
            )
        elif "resource-skipped" in reasons:
            record["error"] = (
                f"AST analysis skipped files beyond the {JS_AST_MAX_INPUT_BYTES:,}-byte "
                "per-file memory-safety limit; bounded raw-text and YARA analysis still ran."
            )
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

# These rules describe ordinary extension capabilities rather than an abuse
# path. A large extension commonly uses each one in several bundled modules;
# emitting one finding per file makes the report look like a list of incidents
# even though the classification policy already treats these signals as
# contextual. Keep the paths and occurrence count, but surface one concise
# finding. Do not add correlated, observed, provenance, or AST rules here:
# repeated high-specificity evidence must remain individually reviewable. The
# AST dynamic-call rule is explicitly weak/contextual, so it is safe to merge
# its repeated occurrences while retaining all source paths and the count.
# Weak secret-reference markers follow the same rule: repeated references are
# still retained as paths/counts, but should not read like separate incidents.
_CONTEXTUAL_OCCURRENCE_RULES = frozenset({
    "ast-dynamic-call-target",
    "dynamic-code-loading",
    "dynamic-shell-execution",
    "encoded-dynamic-execution",
    "filesystem-access",
    "network-access",
    "obfuscation",
    "process-execution",
})

# A repeated high-specificity semantic chain can occur in several bundled
# modules (for example, one client module per provider). It remains review
# evidence, but repeating the same sentence once per file makes a report look
# like several independent incidents. Aggregate only this narrowly defined
# review signal and retain every source path/count in evidence. Correlated
# download/execute, persistence, and credential-exfiltration findings remain
# separate because multiple distinct paths are decision-relevant there.
_REVIEW_OCCURRENCE_RULES = frozenset({"remote-credential-broker"})


def _is_contextual_occurrence_rule(rule_id: str) -> bool:
    """Return whether repeated weak observations can share one report row."""
    return rule_id in _CONTEXTUAL_OCCURRENCE_RULES or rule_id.startswith("secret-reference:")


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that share a finding_id (identical rule + file_refs +
    evidence summary) to the first occurrence, preserving order. Multiple
    analyzers and code paths can surface the same fact; the report should state
    it once. Then aggregate only repeated, explicitly contextual capability
    notes. Scoring is unaffected by the aggregation because component scores
    use max(), while weak-context scoring reflects surfaced notes rather than
    every duplicate file occurrence."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.finding_id in seen:
            continue
        seen.add(finding.finding_id)
        unique.append(finding)
    return _aggregate_contextual_findings(unique)


def _aggregate_contextual_findings(findings: list[Finding]) -> list[Finding]:
    """Merge narrowly repeatable notes without hiding evidence.

    A finding remains separate when its rule is not in the allowlist or when
    policy has promoted it beyond the allowed actionability. Aggregated
    findings carry the union of file references and an occurrence count so
    callers can still investigate every location and distinguish one use from
    many uses.
    """
    grouped: dict[tuple[str, str, str, str, str], Finding] = {}
    occurrence_counts: dict[tuple[str, str, str, str, str], int] = {}
    observation_counts: dict[tuple[str, str, str, str, str], int] = {}
    output: list[Finding] = []

    for finding in findings:
        # The AST dynamic-call summary includes the source path and a
        # per-file count, so using it as a grouping key would defeat the
        # aggregation. Other contextual rules intentionally retain distinct
        # summaries when they describe different evidence.
        summary_key = "" if finding.rule_id == "ast-dynamic-call-target" else finding.evidence_summary
        key = (
            finding.rule_id,
            finding.category,
            finding.severity,
            finding.evidence_type,
            summary_key,
        )
        aggregateable = (
            _is_contextual_occurrence_rule(finding.rule_id)
            and finding_actionability(finding) == "contextual"
        ) or (
            finding.rule_id in _REVIEW_OCCURRENCE_RULES
            and finding_actionability(finding) == "review"
        )
        if not aggregateable:
            output.append(finding)
            continue

        first = grouped.get(key)
        if first is None:
            grouped[key] = finding
            occurrence_counts[key] = 1
            observation_counts[key] = _contextual_observation_count(finding)
            if finding.rule_id == "ast-dynamic-call-target":
                evidence = dict(finding.evidence or {})
                evidence["target_count"] = observation_counts[key]
                finding.evidence = evidence
                finding.evidence_summary = (
                    f"AST found {observation_counts[key]} computed call target(s) in "
                    f"{len(finding.file_refs)} file(s); see occurrence_files for paths."
                )
            output.append(finding)
            continue

        occurrence_counts[key] += 1
        observation_counts[key] += _contextual_observation_count(finding)
        first.file_refs = sorted(set(first.file_refs).union(finding.file_refs))
        evidence = dict(first.evidence or {})
        evidence["occurrence_count"] = occurrence_counts[key]
        evidence["occurrence_files"] = list(first.file_refs)
        if first.rule_id == "ast-dynamic-call-target":
            evidence["count"] = observation_counts[key]
            evidence["target_count"] = observation_counts[key]
            first.evidence_summary = (
                f"AST found {observation_counts[key]} computed call target(s) in "
                f"{len(first.file_refs)} file(s); see occurrence_files for paths."
            )
        first.evidence = evidence
        first.finding_id = _stable_id(
            f"{first.extension_id}:{first.version}:{first.rule_id}:"
            f"{','.join(first.file_refs)}:{first.evidence_summary}"
        )

    return output


def _contextual_observation_count(finding: Finding) -> int:
    """Return the number represented by one contextual finding.

    Most findings represent one occurrence. The AST dynamic-call rule emits
    one finding per file and stores the number of computed targets in
    ``evidence.count``; preserve that total when files are merged.
    """
    if finding.rule_id == "ast-dynamic-call-target":
        try:
            return max(1, int((finding.evidence or {}).get("count") or 1))
        except (TypeError, ValueError):
            return 1
    return 1


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
    dynamic_call_targets: list[dict[str, Any]] = []
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
        if rule_id == "ast-dynamic-call-target":
            dynamic_call_targets.append(item)
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
    if dynamic_call_targets:
        severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        representative = max(
            dynamic_call_targets,
            key=lambda item: severity_order.get(str(item.get("severity") or "MEDIUM"), 2),
        )
        severity = str(representative.get("severity") or "MEDIUM")
        if severity not in _SEVERITY_TO_CONFIDENCE:
            severity = "MEDIUM"
        line = representative.get("line")
        examples = [str(item.get("detail") or "computed call target") for item in dynamic_call_targets[:3]]
        summary = (
            f"AST found {len(dynamic_call_targets)} computed call target(s) in {rel}; "
            f"representative examples: {'; '.join(examples)}"
        )
        findings.append(_finding(
            extension_id,
            version,
            "ast-dynamic-call-target",
            "code",
            severity,
            _SEVERITY_TO_CONFIDENCE[severity],
            summary,
            [rel],
            "Treat computed dispatch as contextual only unless a separate rule resolves the target to a sensitive sink or establishes attacker control.",
            evidence={"line": line, "count": len(dynamic_call_targets)} if isinstance(line, int) else {"count": len(dynamic_call_targets)},
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
    *,
    evidence_type: str = "static",
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
        evidence_type=evidence_type,
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
    rule_ids = {finding.rule_id for finding in findings}
    if any(finding.rule_id == "marketplace-removed-package" and _is_removed_malware(finding.evidence) for finding in findings):
        return 100
    return max_calibrated_score("confirmed_intelligence", rule_ids)


def _correlated_score(findings: list[Finding]) -> int:
    # A rule ID can be deliberately reclassified as a capability when product
    # controls reduce it from an abuse-path finding. Only findings that remain
    # correlated evidence may drive this score component.
    rule_ids = {
        finding.rule_id
        for finding in findings
        if _finding_evidence_class(finding) == "correlated"
    }
    return max_calibrated_score("correlated_behavior", rule_ids)


def _capability_score(findings: list[Finding]) -> int:
    rule_ids = {finding.rule_id for finding in findings}
    return max_calibrated_score("sensitive_capability", rule_ids)


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
            score = max(score, calibrated_score("dependency", finding.rule_id))
        elif finding.rule_id == "vulnerable-npm-dependency":
            exact = bool((finding.evidence or {}).get("exact"))
            if exact:
                score = max(score, calibrated_score("dependency", "vulnerable-npm-dependency-exact"))
        else:
            score = max(score, calibrated_score("dependency", finding.rule_id))
    return score


def _vulnerability_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if _finding_evidence_class(finding) == "vulnerability":
            score = max(score, finding.score)
    return score


def _observed_score(findings: list[Finding]) -> int:
    rule_ids = {finding.rule_id for finding in findings}
    return max_calibrated_score("observed_behavior", rule_ids)


def _proven_observed_score(findings: list[Finding]) -> int:
    rule_ids = {finding.rule_id for finding in findings}
    return max_calibrated_score("proven_observed_behavior", rule_ids)


def _posture_score(findings: list[Finding]) -> int:
    rule_ids = {finding.rule_id for finding in findings}
    return max_calibrated_score("posture", rule_ids)


def _exposure_score(findings: list[Finding]) -> int:
    rule_ids = {finding.rule_id for finding in findings}
    return max_calibrated_score("cross_extension_exposure", rule_ids)


def _reputation_score(findings: list[Finding]) -> int:
    rule_ids = {finding.rule_id for finding in findings if _finding_evidence_class(finding) == "reputation"}
    return max_calibrated_score("reputation", rule_ids)


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
    # The evidence class is the source of truth for intelligence-backed
    # findings. This keeps exact malicious advisory matches aligned with the
    # same confirmed-malware path as hash and threat-feed matches while
    # leaving ordinary vulnerability advisories reviewable/blockable without a
    # malware label.
    if _finding_evidence_class(finding) == "confirmed":
        return True
    if finding.rule_id in CONFIRMED_RULES:
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
