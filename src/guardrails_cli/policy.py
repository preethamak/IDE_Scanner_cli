from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "guardrails.enterprise-policy.v1"
CAPABILITY_POLICY_SCHEMA = "guardrails.capability-policy.v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
EXTENSION_ID = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$")
RELATIONSHIPS = {"extensionPack", "extensionDependencies", "extension_pack", "extension_dependency"}


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
        _validate_relationship_contract(entry, index, entries)


def _validate_relationship_contract(entry: dict[str, Any], index: int, entries: list[Any]) -> None:
    contract = entry.get("relationship_contract")
    if contract is None:
        return
    if not isinstance(contract, dict):
        raise ValueError(f"GuardRails policy entry {index} has an invalid relationship contract.")
    declared = contract.get("declared")
    if not isinstance(declared, list) or not isinstance(contract.get("requires_separate_review"), bool):
        raise ValueError(f"GuardRails policy entry {index} has an invalid relationship contract.")
    seen: set[tuple[str, str]] = set()
    requires_review = False
    for relationship_index, item in enumerate(declared):
        if not isinstance(item, dict):
            raise ValueError(f"GuardRails policy entry {index} relationship {relationship_index} is not an object.")
        extension_id = str(item.get("extension_id") or "")
        relationship = str(item.get("relationship") or "")
        status = str(item.get("status") or "")
        version = item.get("resolved_version")
        artifact_sha256 = item.get("resolved_artifact_sha256")
        key = (relationship, extension_id.lower())
        if relationship not in RELATIONSHIPS or not EXTENSION_ID.fullmatch(extension_id) or not status or key in seen:
            raise ValueError(f"GuardRails policy entry {index} has an invalid declared extension relationship.")
        if version is not None and not isinstance(version, str):
            raise ValueError(f"GuardRails policy entry {index} has an invalid related release version.")
        if artifact_sha256 is not None and (not isinstance(artifact_sha256, str) or not SHA256.fullmatch(artifact_sha256)):
            raise ValueError(f"GuardRails policy entry {index} has an invalid related artifact SHA-256.")
        seen.add(key)
        requires_review = requires_review or not _related_release_approved(item, entries)
    if requires_review and contract["requires_separate_review"] is not True:
        raise ValueError(f"GuardRails policy entry {index} must require separate review for incomplete related releases.")


def _related_release_approved(item: dict[str, Any], entries: list[Any], visited: frozenset[tuple[str, str, str]] = frozenset()) -> bool:
    if item.get("status") not in {"scanned", "already_scanned_as_requested_target"}:
        return False
    child_id = str(item.get("extension_id") or "").lower()
    child_version = item.get("resolved_version")
    child_hash = str(item.get("resolved_artifact_sha256") or "").lower()
    if not child_version or not SHA256.fullmatch(child_hash):
        return False
    identity = (child_id, str(child_version), child_hash)
    for child in entries:
        if not isinstance(child, dict) or str(child.get("extension_id") or "").lower() != child_id or child.get("version") != child_version or str(child.get("artifact_sha256") or "").lower() != child_hash or child.get("analysis_status") != "complete" or child.get("decision") not in {"allow", "exception"}:
            continue
        if identity in visited:
            return True
        contract = child.get("relationship_contract")
        if contract is None:
            return True
        return isinstance(contract, dict) and contract.get("requires_separate_review") is False and isinstance(contract.get("declared"), list) and all(
            isinstance(relation, dict) and _related_release_approved(relation, entries, visited | {identity})
            for relation in contract["declared"]
        )
    return False


def _requires_relationship_review(entry: dict[str, Any], entries: list[Any]) -> bool:
    contract = entry.get("relationship_contract")
    if contract is None:
        return False
    if not isinstance(contract, dict) or not isinstance(contract.get("declared"), list):
        return True
    return contract.get("requires_separate_review") is not False or any(
        not isinstance(item, dict) or not _related_release_approved(item, entries)
        for item in contract["declared"]
    )


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


def load_capability_policy_bundle(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Capability policy bundle is not valid JSON: {target}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != CAPABILITY_POLICY_SCHEMA or payload.get("default_action") != "deny":
        raise ValueError("Unsupported GuardRails capability policy bundle.")
    expected = str(payload.get("policy_hash") or "").lower()
    unsigned = {key: value for key, value in payload.items() if key != "policy_hash"}
    actual = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    if not SHA256.fullmatch(expected) or actual != expected:
        raise ValueError("Capability policy bundle integrity check failed.")
    if not isinstance(payload.get("evaluations"), list):
        raise ValueError("Capability policy bundle has no evaluations.")
    _capability_evaluations(payload)
    return payload


def _capability_evaluations(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    evaluations = bundle.get("evaluations")
    if not isinstance(evaluations, list):
        raise ValueError("Capability policy bundle must contain evaluations.")
    seen: set[str] = set()
    for entry in evaluations:
        if not isinstance(entry, dict) or not isinstance(entry.get("subject_id"), str) or not entry["subject_id"].strip():
            raise ValueError("Capability policy contains an invalid evaluation.")
        if entry["subject_id"] in seen or entry.get("outcome") not in {"allow", "prompt", "deny"}:
            raise ValueError("Capability policy contains a duplicate subject or unsupported outcome.")
        seen.add(entry["subject_id"])
        requests = entry.get("requests")
        if not isinstance(requests, list) or any(not isinstance(row, dict) or row.get("decision") not in {"allow", "prompt", "deny"} for row in requests):
            raise ValueError("Capability policy contains invalid request decisions.")
        if entry["outcome"] == "allow" and (not requests or any(row["decision"] != "allow" for row in requests)):
            raise ValueError("Capability allow requires explicit allowed request evidence.")
    return evaluations


def check_capability_policy(bundle: dict[str, Any]) -> dict[str, Any]:
    results = []
    for entry in _capability_evaluations(bundle):
        outcome = str(entry.get("outcome") or "deny")
        results.append({"subject_id": str(entry.get("subject_id") or "unknown"), "outcome": outcome, "requests": list(entry.get("requests") or [])})
    denied = [item for item in results if item["outcome"] == "deny"]
    prompts = [item for item in results if item["outcome"] == "prompt"]
    return {"schema": "guardrails.capability-policy-check.v1", "policy_hash": bundle.get("policy_hash"), "results": results, "summary": {"subjects": len(results), "allowed": len(results) - len(denied) - len(prompts), "denied": len(denied), "approval_required": len(prompts), "compliant": not denied and not prompts}}


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
            relationship_contract = entry.get("relationship_contract") if isinstance(entry.get("relationship_contract"), dict) else {
                "declared": [],
                "requires_separate_review": False,
            }
            requires_relationship_review = _requires_relationship_review(entry, list(allowed.values()))
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
                "relationship_contract": relationship_contract,
                "relationship_review": "required" if requires_relationship_review else "not_required",
                "hash_verification": "required_not_available_for_installed_directory",
                "reason": (
                    "The installed ID and version match an approved exact release, but the local directory is not itself the published VSIX. "
                    "Verify the published artifact with policy verify before treating the installation as compliant. "
                    + ("Declared related extensions require their own completed exact-release review; this parent approval does not cover them." if requires_relationship_review else "")
                ).strip(),
            })
        else:
            results.append({
                "extension_id": extension_id,
                "version": version,
                "client": str(installation.get("client") or "unknown"),
                "status": "blocked",
                "decision": "deny",
                "artifact_sha256": "",
                "relationship_contract": {"declared": [], "requires_separate_review": False},
                "relationship_review": "not_applicable",
                "hash_verification": "not_applicable",
                "reason": "The exact extension ID and version are not present in the GuardRails allowlist.",
            })
    blocked = [item for item in results if item["status"] == "blocked"]
    unverified = [item for item in results if item["status"] == "version_allowed_unverified"]
    relationship_review_required = [item for item in results if item.get("relationship_review") == "required"]
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
            "relationship_review_required": len(relationship_review_required),
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
    relationship_review_required = any(
        _requires_relationship_review(entry, bundle.get("entries") or [])
        for entry in entries
    )
    status = "relationship_review_required" if entries and relationship_review_required else "allowed" if entries else "blocked"
    return {
        "schema": "guardrails.policy-verify.v1",
        "policy_hash": str(bundle.get("policy_hash") or ""),
        "artifact": str(target.resolve()),
        "artifact_sha256": artifact_sha256,
        "status": status,
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
            "The artifact bytes match an approved parent release, but declared related extensions require their own completed exact-release review."
            if relationship_review_required
            else "The artifact bytes match an approved exact release in the GuardRails policy."
            if entries
            else "The artifact bytes do not match any approved exact release in the GuardRails policy."
        ),
    }
