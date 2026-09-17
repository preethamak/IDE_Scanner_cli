from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "guardrails.enterprise-policy.v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
EXTENSION_ID = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$")


def load_policy_bundle(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        raise ValueError(f"Policy bundle does not exist: {target}")
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Policy bundle is not valid JSON: {target}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != POLICY_SCHEMA:
        raise ValueError(f"Unsupported GuardRails policy bundle: {target}")
    if payload.get("default_action") != "deny":
        raise ValueError("GuardRails policy bundles must use default_action=deny.")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise ValueError("GuardRails policy bundle has no exact-release entries.")
    _validate_entries(entries)
    expected_hash = str(payload.get("policy_hash") or "")
    if len(expected_hash) != 64 or any(character not in "0123456789abcdef" for character in expected_hash.lower()):
        raise ValueError("GuardRails policy bundle has no valid policy_hash.")
    if compute_policy_hash(payload) != expected_hash.lower():
        raise ValueError("GuardRails policy bundle integrity check failed: policy_hash does not match its contents.")
    _validate_enforcement(payload)
    return payload


def _validate_entries(entries: list[Any]) -> None:
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"GuardRails policy entry {index} is not an object.")
        extension_id = str(entry.get("extension_id") or "")
        version = str(entry.get("version") or "")
        decision = str(entry.get("decision") or "").lower()
        artifact_sha256 = str(entry.get("artifact_sha256") or "").lower()
        if not EXTENSION_ID.fullmatch(extension_id):
            raise ValueError(f"GuardRails policy entry {index} has an invalid extension_id.")
        if not version:
            raise ValueError(f"GuardRails policy entry {index} requires an exact version.")
        identity = (extension_id.lower(), version)
        if identity in seen:
            raise ValueError(f"GuardRails policy contains duplicate exact release {extension_id}@{version}.")
        seen.add(identity)
        if decision not in {"allow", "exception"}:
            raise ValueError(f"GuardRails policy entry {index} is not deployable: decision must be allow or exception.")
        if not SHA256.fullmatch(artifact_sha256):
            raise ValueError(f"GuardRails policy entry {index} requires an exact artifact SHA-256.")
        if str(entry.get("analysis_status") or "") != "complete":
            raise ValueError(f"GuardRails policy entry {index} does not have complete analysis.")


def _validate_enforcement(payload: dict[str, Any]) -> None:
    enforcement = payload.get("enforcement")
    if not isinstance(enforcement, dict):
        raise ValueError("GuardRails policy bundle has no enforcement contract.")
    vscode = enforcement.get("vscode")
    settings = vscode.get("settings") if isinstance(vscode, dict) else None
    allowed = settings.get("extensions.allowed") if isinstance(settings, dict) else None
    if not isinstance(allowed, dict) or allowed.get("*") is not False:
        raise ValueError("GuardRails policy bundle must deny unknown extensions by default.")
    if settings.get("extensions.autoUpdate") is not False:
        raise ValueError("GuardRails policy bundle must disable automatic extension updates.")
    guardrails = enforcement.get("guardrails")
    if not isinstance(guardrails, dict) or guardrails.get("requires_artifact_sha256") is not True or guardrails.get("requires_complete_analysis") is not True or guardrails.get("requires_capability_contract") is not True:
        raise ValueError("GuardRails policy bundle must require exact artifact identity and complete analysis.")
    allowlist = guardrails.get("exact_release_allowlist")
    entries = payload.get("entries")
    if not isinstance(allowlist, list) or not isinstance(entries, list) or allowlist != entries:
        raise ValueError("GuardRails policy bundle has divergent exact-release allowlists.")
    expected_allowed: dict[str, bool | list[str]] = {"*": False}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        extension_id = str(entry.get("extension_id") or "").lower()
        versions = expected_allowed.get(extension_id)
        if not isinstance(versions, list):
            versions = []
            expected_allowed[extension_id] = versions
        versions.append(str(entry.get("version") or ""))
    for extension_id, versions in expected_allowed.items():
        if isinstance(versions, list):
            expected_allowed[extension_id] = sorted(set(versions))
    if allowed != expected_allowed:
        raise ValueError("GuardRails policy bundle VS Code allowlist does not match its exact releases.")


def compute_policy_hash(payload: dict[str, Any]) -> str:
    canonical = {
        "schema": payload.get("schema"),
        "team_id": payload.get("team_id"),
        "default_action": payload.get("default_action"),
        "enforcement": payload.get("enforcement") or {},
        "entries": payload.get("entries") or [],
        "unresolved": payload.get("unresolved") or [],
    }
    encoded = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def check_installed_extensions(
    bundle: dict[str, Any], installations: list[dict[str, Any]],
) -> dict[str, Any]:
    entries = bundle.get("entries")
    if not isinstance(entries, list):
        raise ValueError("GuardRails policy bundle has no exact-release entries.")
    allowed = {
        (str(entry.get("extension_id") or "").lower(), str(entry.get("version") or "")): entry
        for entry in entries
        if isinstance(entry, dict)
    }
    results: list[dict[str, Any]] = []
    for installation in installations:
        extension_id = str(installation.get("extension_id") or "").strip()
        version = str(installation.get("version") or "").strip()
        entry = allowed.get((extension_id.lower(), version))
        if entry:
            results.append({
                "extension_id": extension_id,
                "version": version,
                "client": str(installation.get("client") or "unknown"),
                "status": "version_allowed_unverified",
                "decision": str(entry.get("decision") or "allow"),
                "artifact_sha256": str(entry.get("artifact_sha256") or ""),
                "capability_contract": entry.get("capability_contract") if isinstance(entry.get("capability_contract"), dict) else {
                    "observed": [],
                    "requires_explicit_review": False,
                    "review_reason": None,
                },
                "hash_verification": "required_not_available_for_installed_directory",
                "reason": "The installed ID and version match an approved exact release, but the local directory is not itself the published VSIX. Verify the published artifact with policy verify before treating the installation as compliant.",
            })
        else:
            results.append({
                "extension_id": extension_id,
                "version": version,
                "client": str(installation.get("client") or "unknown"),
                "status": "blocked",
                "decision": "deny",
                "artifact_sha256": "",
                "hash_verification": "not_applicable",
                "reason": "The exact extension ID and version are not present in the GuardRails allowlist.",
            })
    blocked = [item for item in results if item["status"] == "blocked"]
    unverified = [item for item in results if item["status"] == "version_allowed_unverified"]
    return {
        "schema": "guardrails.policy-check.v1",
        "policy_hash": str(bundle.get("policy_hash") or ""),
        "default_action": "deny",
        "hash_verification": "installed_directory_not_published_artifact",
        "results": results,
        "summary": {
            "installed": len(results),
            "allowed": len(results) - len(blocked),
            "blocked": len(blocked),
            "unverified": len(unverified),
            "compliant": not blocked and not unverified,
        },
    }


def verify_artifact(bundle: dict[str, Any], artifact: str | Path) -> dict[str, Any]:
    target = Path(artifact)
    if not target.is_file():
        raise ValueError(f"Published artifact does not exist: {target}")
    digest = hashlib.sha256()
    try:
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ValueError(f"Could not hash published artifact: {target}") from exc
    artifact_sha256 = digest.hexdigest()
    entries = [
        entry for entry in bundle.get("entries", [])
        if isinstance(entry, dict)
        and str(entry.get("decision") or "").lower() in {"allow", "exception"}
        and str(entry.get("artifact_sha256") or "").lower() == artifact_sha256
    ]
    return {
        "schema": "guardrails.policy-verify.v1",
        "policy_hash": str(bundle.get("policy_hash") or ""),
        "artifact": str(target.resolve()),
        "artifact_sha256": artifact_sha256,
        "status": "allowed" if entries else "blocked",
        "matched_releases": [
            {
                "extension_id": str(entry.get("extension_id") or ""),
                "version": str(entry.get("version") or ""),
                "decision": str(entry.get("decision") or "allow"),
            }
            for entry in entries
        ],
        "hash_verification": "published_artifact_sha256_exact",
        "reason": (
            "The artifact bytes match an approved exact release in the GuardRails policy."
            if entries
            else "The artifact bytes do not match any approved exact release in the GuardRails policy."
        ),
    }
