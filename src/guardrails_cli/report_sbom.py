from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from .report_reader import report_view


CYCLONEDX_FORMAT = "CycloneDX"
CYCLONEDX_SPEC_VERSION = "1.5"


def build_cyclonedx_sbom(report: dict[str, Any]) -> dict[str, Any]:
    """Project exact extension artifacts and packaged dependencies into CycloneDX.

    The source report remains authoritative. This export intentionally omits
    source previews, findings, and notification targets so it is safe to hand to
    dependency and asset-inventory systems.
    """
    view = report_view(report)
    metadata = view.get("metadata") if isinstance(view.get("metadata"), dict) else {}
    extensions = [item for item in view.get("extensions", []) if isinstance(item, dict)]
    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    dependency_components: dict[str, dict[str, Any]] = {}

    for extension in extensions:
        extension_id = str(extension.get("extension_id") or "").strip()
        version = str(extension.get("version") or "").strip()
        if not extension_id or not version:
            continue
        ref = f"pkg:generic/vscode-extension/{extension_id}@{version}"
        artifact_hash = _artifact_hash(extension)
        component: dict[str, Any] = {
            "type": "application",
            "bom-ref": ref,
            "name": extension_id,
            "version": version,
            "purl": ref,
            "properties": _extension_properties(extension),
        }
        if artifact_hash:
            component["hashes"] = [{"alg": "SHA-256", "content": artifact_hash}]
        components.append(component)
        dependency_refs: list[str] = []
        raw_dependencies = extension.get("dependencies")
        if isinstance(raw_dependencies, dict):
            for name, spec in sorted(raw_dependencies.items()):
                package = str(name).strip()
                version_spec = str(spec).strip()
                if not package or not version_spec:
                    continue
                dependency_ref = f"pkg:npm/{package}@{version_spec}"
                dependency_refs.append(dependency_ref)
                dependency_components.setdefault(
                    dependency_ref,
                    {
                        "type": "library",
                        "bom-ref": dependency_ref,
                        "name": package,
                        "version": version_spec,
                        "purl": dependency_ref,
                        "properties": [{"name": "guardrails:dependency_scope", "value": "runtime"}],
                    },
                )
        dependencies.append({"ref": ref, "dependsOn": dependency_refs})

    components.extend(dependency_components.values())
    created_at = str(metadata.get("created_at") or view.get("created_at") or _now())
    scan_id = str(metadata.get("scan_id") or view.get("scan_id") or "guardrails-report")
    return {
        "bomFormat": CYCLONEDX_FORMAT,
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, f'https://abscissa.dev/guardrails/reports/{scan_id}')}",
        "version": 1,
        "metadata": {
            "timestamp": created_at,
            "tools": [{"vendor": "Abscissa", "name": "GuardRails", "version": str(metadata.get("scanner_version") or metadata.get("scanner_build") or "unknown")}],
            "properties": _report_properties(metadata, len(extensions)),
        },
        "components": components,
        "dependencies": dependencies,
    }


def _artifact_hash(extension: dict[str, Any]) -> str:
    inventory = extension.get("artifact_inventory") if isinstance(extension.get("artifact_inventory"), dict) else {}
    for value in (extension.get("artifact_sha256"), inventory.get("vsix_hash"), inventory.get("package_hash")):
        candidate = str(value or "").lower()
        if len(candidate) == 64 and all(char in "0123456789abcdef" for char in candidate):
            return candidate
    return ""


def _extension_properties(extension: dict[str, Any]) -> list[dict[str, str]]:
    properties = []
    for name, value in (
        ("guardrails:decision", extension.get("decision")),
        ("guardrails:severity", extension.get("severity")),
        ("guardrails:coverage_percent", extension.get("coverage_percent")),
    ):
        if value not in (None, ""):
            properties.append({"name": name, "value": str(value)})
    return properties


def _report_properties(metadata: dict[str, Any], extension_count: int) -> list[dict[str, str]]:
    values = [("guardrails:extension_count", extension_count), ("guardrails:ruleset_version", metadata.get("ruleset_version")), ("guardrails:scanner_build", metadata.get("scanner_build"))]
    return [{"name": name, "value": str(value)} for name, value in values if value not in (None, "")]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
