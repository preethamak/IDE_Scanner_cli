from __future__ import annotations

import gzip
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from datetime import UTC, datetime
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse
from typing import Any

MARKETPLACE_EXTENSIONQUERY_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery?api-version=7.2-preview.1"
OPENVSX_API_URL = "https://open-vsx.org/api"
REMOVED_PACKAGES_URL = "https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md"
REMOVED_ROW = re.compile(r"^\|\s*(?P<id>[a-zA-Z0-9._-]+)\s*\|\s*(?P<date>[0-9/]+)\s*\|\s*(?P<type>[^|]+?)\s*\|", re.M)
LOW_INSTALL_THRESHOLD = 100
HIGH_INSTALL_RATING_MISMATCH_THRESHOLD = 50_000
STALE_EXTENSION_DAYS = 730
STALE_REPOSITORY_DAYS = 730
MARKETPLACE_BATCH_SIZE = 25
OSV_BATCH_SIZE = 100
VSIX_ASSET_TYPE = "Microsoft.VisualStudio.Services.VSIXPackage"
MAX_VSIX_DOWNLOAD_BYTES = 50 * 1024 * 1024
MAX_CONFIGURED_VSIX_DOWNLOAD_BYTES = 512 * 1024 * 1024
VSIX_DOWNLOAD_TIMEOUT = 30
EXTENSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$")


class MarketplaceDownloadError(RuntimeError):
    """Raised when a marketplace VSIX cannot be resolved or downloaded safely."""


IMPERSONATION_TARGETS = (
    ("microsoft", "python", "Python"),
    ("microsoft", "vscode-cpptools", "C/C++"),
    ("github", "copilot-chat", "GitHub Copilot"),
    ("openai", "chatgpt", "ChatGPT"),
    ("anthropic", "claude-code", "Claude Code"),
    ("ms-toolsai", "jupyter", "Jupyter"),
    ("ms-azuretools", "vscode-docker", "Docker"),
)


def enrich_registry(extensions: list[Any], online: bool = False) -> dict[str, Any]:
    if not online:
        return {"enabled": False, "findings": [], "errors": []}

    errors: list[dict[str, str]] = []
    removed, removed_error = _fetch_removed_packages()
    if removed_error:
        errors.append({"source": "removed-packages", "message": removed_error})

    marketplace_metadata, marketplace_errors = _fetch_marketplace_metadata_many([
        extension.extension_id for extension in extensions
    ])
    errors.extend(marketplace_errors)
    osv_by_extension, osv_errors = _check_osv_many(extensions)
    errors.extend(osv_errors)
    repo_metadata, repo_errors = _fetch_repository_metadata_many([
        str(getattr(extension, "repository", "") or "") for extension in extensions
    ])
    errors.extend(repo_errors)

    findings: list[dict[str, Any]] = []
    for extension in extensions:
        removed_entry = removed.get(extension.extension_id.lower())
        if removed_entry:
            removed_type = str(removed_entry["type"]).strip()
            removed_type_lower = removed_type.lower()
            removed_as_malware = removed_type_lower == "malware"
            if removed_as_malware:
                severity = "CRITICAL"
                confidence = 0.96
            elif removed_type_lower in {"suspicious", "untrustworthy", "impersonation"}:
                severity = "HIGH"
                confidence = 0.9
            else:
                severity = "MEDIUM"
                confidence = 0.82
            findings.append({
                "extension_id": extension.extension_id,
                "severity": severity,
                "confidence": confidence,
                "category": "registry",
                "rule_id": "marketplace-removed-malware" if removed_as_malware else "marketplace-removed-package",
                "evidence_summary": f"Extension appears in Microsoft's removed package list as {removed_type}.",
                "evidence": removed_entry,
            })
        findings.extend(osv_by_extension.get(extension.extension_id, []))
        findings.extend(_marketplace_metadata_findings(extension.extension_id, marketplace_metadata.get(extension.extension_id)))
        findings.extend(_repository_metadata_findings(
            extension.extension_id,
            repo_metadata.get(str(getattr(extension, "repository", "") or "")),
        ))
    return {"enabled": True, "mode": "batched", "findings": findings, "errors": errors}


def parse_marketplace_reference(value: str) -> str:
    """Normalize a user-supplied marketplace reference (publisher.name or a
    marketplace.visualstudio.com / vscode:extension URL) down to a bare
    ``publisher.name`` extension id. Raises MarketplaceDownloadError on
    anything that doesn't resolve to a well-formed id."""
    raw = str(value or "").strip()
    if not raw:
        raise MarketplaceDownloadError("Marketplace reference is empty.")

    if EXTENSION_ID_RE.match(raw):
        return raw

    parsed = urlparse(raw)
    if parsed.scheme in {"vscode", "vscode-insiders"}:
        # vscode:extension/publisher.name parses with an empty netloc and the
        # "extension/..." segment folded into path; handle both that and the
        # (rarer) vscode://extension/publisher.name double-slash form.
        rest = f"{parsed.netloc}/{parsed.path}" if parsed.netloc else parsed.path
        rest = re.sub(r"/+", "/", rest).strip("/")
        prefix = "extension/"
        candidate = rest[len(prefix):] if rest.startswith(prefix) else ""
        if EXTENSION_ID_RE.match(candidate):
            return candidate

    if parsed.scheme in {"http", "https"} and parsed.netloc.lower().endswith("marketplace.visualstudio.com"):
        query = parse_qs(parsed.query)
        item_name = (query.get("itemName") or [""])[0]
        if EXTENSION_ID_RE.match(item_name):
            return item_name

    raise MarketplaceDownloadError(f"Could not resolve a publisher.name extension id from {raw!r}.")


def download_marketplace_vsix(
    extension_id: str,
    version: str | None = None,
    destination_dir: Path | str | None = None,
    max_bytes: int | None = None,
    timeout: int | None = None,
    registry_out: dict[str, str] | None = None,
) -> Path:
    """Resolve `publisher.name` (optionally pinned to `version`) against the VS
    Marketplace gallery API and download the VSIX package to a temp file.

    Raises MarketplaceDownloadError for any resolution/network/size failure.
    Caller owns the returned path and is responsible for deleting it."""
    max_bytes = _bounded_positive_env("IDE_SCANNER_MAX_VSIX_BYTES", MAX_VSIX_DOWNLOAD_BYTES, MAX_CONFIGURED_VSIX_DOWNLOAD_BYTES) if max_bytes is None else max_bytes
    timeout = _bounded_positive_env("IDE_SCANNER_VSIX_DOWNLOAD_TIMEOUT", VSIX_DOWNLOAD_TIMEOUT, 600) if timeout is None else timeout
    resolved_id = parse_marketplace_reference(extension_id)
    metadata, error = _fetch_marketplace_metadata(resolved_id)
    if error or not metadata or not metadata.get("found"):
        metadata, openvsx_error = _fetch_openvsx_metadata(resolved_id)
        if openvsx_error:
            reasons = "; ".join(item for item in (error, openvsx_error) if item)
            raise MarketplaceDownloadError(f"Registry lookup failed for {resolved_id}: {reasons}")
    if not metadata or not metadata.get("found"):
        raise MarketplaceDownloadError(f"Extension {resolved_id} was not found on VS Marketplace or Open VSX.")

    publisher = metadata.get("publisher") or resolved_id.split(".", 1)[0]
    name = metadata.get("extension_name") or resolved_id.split(".", 1)[1]
    target_version = version or metadata.get("version") or ""
    if not target_version:
        raise MarketplaceDownloadError(f"Could not resolve a version to download for {resolved_id}.")

    download_url = str(metadata.get("download_url") or "") or (
        f"https://marketplace.visualstudio.com/_apis/public/gallery/publishers/{publisher}/"
        f"vsextensions/{name}/{target_version}/vspackage"
    )
    download_urls = [download_url]
    if metadata.get("registry") != "openvsx":
        openvsx_metadata, _ = _fetch_openvsx_metadata(resolved_id)
        openvsx_url = str((openvsx_metadata or {}).get("download_url") or "")
        # Never satisfy an exact-version request with Open VSX's latest
        # artifact. If the registries do not expose the same version, fail
        # closed instead of silently scanning and relabelling another release.
        openvsx_matches = not version or str((openvsx_metadata or {}).get("version") or "") == target_version
        if openvsx_matches and openvsx_url and openvsx_url not in download_urls:
            download_urls.append(openvsx_url)

    destination_root = Path(destination_dir) if destination_dir else Path(tempfile.gettempdir())
    destination_root.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", f"{resolved_id}-{target_version}")
    fd, tmp_path = tempfile.mkstemp(prefix=f"ide-scanner-mkt-{safe_name}-", suffix=".vsix", dir=str(destination_root))
    out_path = Path(tmp_path)

    try:
        with os.fdopen(fd, "wb") as handle:
            failures: list[str] = []
            for candidate_url in download_urls:
                handle.seek(0)
                handle.truncate(0)
                try:
                    _download_to_file(candidate_url, handle, max_bytes=max_bytes, timeout=timeout)
                    if registry_out is not None:
                        registry_out["registry"] = "openvsx" if "open-vsx.org" in candidate_url else "vs-marketplace"
                    break
                except MarketplaceDownloadError as exc:
                    failures.append(str(exc))
            else:
                raise MarketplaceDownloadError("; ".join(failures))
    except MarketplaceDownloadError:
        out_path.unlink(missing_ok=True)
        raise
    except (OSError, urllib.error.URLError, subprocess.SubprocessError) as exc:
        out_path.unlink(missing_ok=True)
        raise MarketplaceDownloadError(f"Failed to download VSIX for {resolved_id}: {exc}") from exc

    if out_path.stat().st_size == 0:
        out_path.unlink(missing_ok=True)
        raise MarketplaceDownloadError(f"Downloaded VSIX for {resolved_id} was empty.")

    _degzip_if_needed(out_path)
    return out_path


def _bounded_positive_env(name: str, default: int, upper_bound: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise MarketplaceDownloadError(f"{name} must be an integer") from exc
    if value < 1 or value > upper_bound:
        raise MarketplaceDownloadError(f"{name} must be between 1 and {upper_bound}")
    return value


MARKETPLACE_SEARCH_TEXT_FILTER = 10
MARKETPLACE_SORT_BY_RELEVANCE = 0
MARKETPLACE_SORT_BY_INSTALLS = 4
MAX_SEARCH_RESULTS = 25
ICON_SMALL_ASSET_TYPE = "Microsoft.VisualStudio.Services.Icons.Small"
ICON_DEFAULT_ASSET_TYPE = "Microsoft.VisualStudio.Services.Icons.Default"


def search_marketplace_extensions(query: str, page_size: int = MAX_SEARCH_RESULTS) -> list[dict[str, Any]]:
    """Free-text search against the VS Marketplace gallery (extensionquery,
    filterType 10). Returns lightweight result rows for a search-as-you-type
    UI: id, display name, publisher, description, install count, rating,
    icon URL, and whether the publisher is domain-verified. No download or
    scan happens here -- this is metadata-only, read-only, and safe to call
    directly from a request handler."""
    query = query.strip()
    if not query:
        return []
    page_size = max(1, min(int(page_size or MAX_SEARCH_RESULTS), MAX_SEARCH_RESULTS))
    body = json.dumps({
        "filters": [{
            "criteria": [{"filterType": MARKETPLACE_SEARCH_TEXT_FILTER, "value": query}],
            "pageNumber": 1,
            "pageSize": page_size,
            "sortBy": MARKETPLACE_SORT_BY_INSTALLS,
        }],
        "flags": 914,
    }).encode("utf-8")
    try:
        data = _http_post_json(MARKETPLACE_EXTENSIONQUERY_URL, body, timeout=15)
        raw_results = data.get("results", [{}])[0].get("extensions", [])
    except (AttributeError, IndexError, OSError, urllib.error.URLError, json.JSONDecodeError):
        raw_results = []
    results: list[dict[str, Any]] = []
    for raw in raw_results:
        if not isinstance(raw, dict):
            continue
        row = _normalize_marketplace_search_row(raw)
        if row:
            results.append(row)
    try:
        openvsx = _search_openvsx_extensions(query, page_size)
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        openvsx = []
    seen = {str(item.get("extension_id") or "").lower() for item in results}
    results.extend(item for item in openvsx if str(item.get("extension_id") or "").lower() not in seen)
    return results[:page_size]


def _search_openvsx_extensions(query: str, page_size: int) -> list[dict[str, Any]]:
    url = f"{OPENVSX_API_URL}/-/search?query={quote(query)}&size={page_size}"
    data = json.loads(_http_get_text(url, timeout=15))
    extensions = data.get("extensions") if isinstance(data, dict) else []
    return [_normalize_openvsx_search_row(item) for item in extensions or [] if isinstance(item, dict)]


def _normalize_openvsx_search_row(raw: dict[str, Any]) -> dict[str, Any]:
    namespace = str(raw.get("namespace") or "")
    name = str(raw.get("name") or "")
    files = raw.get("files") if isinstance(raw.get("files"), dict) else {}
    return {
        "extension_id": f"{namespace}.{name}",
        "display_name": raw.get("displayName") or name,
        "publisher": namespace,
        "publisher_display_name": namespace,
        "publisher_verified": bool(raw.get("verified")),
        "short_description": raw.get("description") or "",
        "version": raw.get("version") or "",
        "last_updated": raw.get("timestamp") or "",
        "install_count": int(raw.get("downloadCount") or 0),
        "rating_average": float(raw.get("averageRating") or 0),
        "rating_count": int(raw.get("reviewCount") or 0),
        "icon_url": files.get("icon") or "",
        "registry": "openvsx",
    }


def _normalize_marketplace_search_row(raw: dict[str, Any]) -> dict[str, Any] | None:
    publisher = raw.get("publisher") if isinstance(raw.get("publisher"), dict) else {}
    publisher_name = publisher.get("publisherName") or ""
    extension_name = raw.get("extensionName") or ""
    if not publisher_name or not extension_name:
        return None
    versions = raw.get("versions") if isinstance(raw.get("versions"), list) else []
    latest_version = versions[0] if versions and isinstance(versions[0], dict) else {}
    stats = _marketplace_stats(raw.get("statistics"))
    files = latest_version.get("files") if isinstance(latest_version.get("files"), list) else []
    icon_url = ""
    for file_entry in files:
        if isinstance(file_entry, dict) and file_entry.get("assetType") in (ICON_SMALL_ASSET_TYPE, ICON_DEFAULT_ASSET_TYPE):
            icon_url = str(file_entry.get("source") or "")
            if file_entry.get("assetType") == ICON_SMALL_ASSET_TYPE:
                break
    return {
        "extension_id": f"{publisher_name}.{extension_name}",
        "display_name": raw.get("displayName") or extension_name,
        "publisher": publisher_name,
        "publisher_display_name": publisher.get("displayName") or publisher_name,
        "publisher_verified": _marketplace_publisher_verified(publisher),
        "short_description": raw.get("shortDescription") or "",
        "version": latest_version.get("version") or "",
        "last_updated": latest_version.get("lastUpdated") or raw.get("lastUpdated") or "",
        "install_count": int(stats.get("install") or 0),
        "rating_average": round(float(stats.get("averagerating") or 0), 2),
        "rating_count": int(stats.get("ratingcount") or 0),
        "icon_url": icon_url,
    }


def _degzip_if_needed(path: Path) -> None:
    """The vspackage endpoint sometimes serves the VSIX gzip-compressed
    (Content-Encoding: gzip) without a matching urllib auto-decode, so the
    raw bytes on disk start with the gzip magic (1f 8b) instead of the PK
    zip signature. Unwrap it in place before scan_vsix() opens it as a
    zipfile."""
    with path.open("rb") as handle:
        header = handle.read(2)
    if header != b"\x1f\x8b":
        return
    decompressed_fd, decompressed_name = tempfile.mkstemp(prefix="ide-scanner-mkt-gunzip-", suffix=".vsix", dir=str(path.parent))
    try:
        with gzip.open(path, "rb") as source, os.fdopen(decompressed_fd, "wb") as target:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                target.write(chunk)
    except OSError as exc:
        Path(decompressed_name).unlink(missing_ok=True)
        raise MarketplaceDownloadError(f"Downloaded VSIX was gzip-encoded but could not be decompressed: {exc}") from exc
    os.replace(decompressed_name, path)


def _download_to_file(url: str, handle: Any, max_bytes: int, timeout: int) -> None:
    request = urllib.request.Request(url, headers={"accept": "application/octet-stream"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            _stream_with_cap(response, handle, max_bytes, url)
        return
    except (OSError, urllib.error.URLError):
        pass

    # Fall back to curl, still enforcing the byte cap on our side while streaming.
    process = subprocess.Popen(
        ["curl", "-L", "--max-time", str(timeout), "-s", url],
        stdout=subprocess.PIPE,
    )
    try:
        assert process.stdout is not None
        _stream_with_cap(process.stdout, handle, max_bytes, url)
    finally:
        process.stdout.close() if process.stdout else None
        process.wait(timeout=timeout)
    if process.returncode != 0:
        raise MarketplaceDownloadError(f"curl exited with status {process.returncode} downloading {url}")


def _stream_with_cap(source: Any, handle: Any, max_bytes: int, url: str) -> None:
    total = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise MarketplaceDownloadError(
                f"VSIX download from {url} exceeded the {max_bytes} byte cap; aborted."
            )
        handle.write(chunk)


def _fetch_removed_packages() -> tuple[dict[str, dict[str, str]], str | None]:
    try:
        cache_path = os.environ.get("IDE_SCANNER_REMOVED_PACKAGES_FILE")
        if cache_path:
            with open(cache_path, encoding="utf-8") as handle:
                text = handle.read()
        else:
            text = _http_get_text(REMOVED_PACKAGES_URL, timeout=15)
    except (OSError, urllib.error.URLError, subprocess.SubprocessError) as exc:
        return {}, str(exc)

    removed: dict[str, dict[str, str]] = {}
    for match in REMOVED_ROW.finditer(text):
        ext_id = match.group("id")
        if ext_id.lower() == "extension identifier":
            continue
        removed[ext_id.lower()] = {"date": match.group("date"), "type": match.group("type").strip()}
    return removed, None


def _check_osv(extension: Any) -> tuple[list[dict[str, Any]], str | None]:
    entries = [
        {"name": name, "version": _normalize_version(version), "exact": bool(re.match(r"^\d+\.\d+\.\d+", str(version)))}
        for name, version in extension.dependencies.items()
        if isinstance(version, str)
    ]
    entries = [entry for entry in entries if entry["version"]]
    if not entries:
        return [], None

    body = json.dumps({
        "queries": [
            {"package": {"name": entry["name"], "ecosystem": "npm"}, "version": entry["version"]}
            for entry in entries
        ]
    }).encode("utf-8")
    try:
        data = _http_post_json("https://api.osv.dev/v1/querybatch", body, timeout=15)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return [], str(exc)

    findings: list[dict[str, Any]] = []
    for index, result in enumerate(data.get("results", [])):
        vulns = result.get("vulns", [])
        if not vulns:
            continue
        dep = entries[index]
        malicious = any(str(vuln.get("id", "")).startswith("MAL-") for vuln in vulns)
        findings.append({
            "extension_id": extension.extension_id,
            "severity": "CRITICAL" if malicious else "HIGH" if dep["exact"] else "MEDIUM",
            "confidence": 0.94 if malicious else 0.82 if dep["exact"] else 0.58,
            "category": "dependency",
            "rule_id": "malicious-npm-dependency" if malicious else "vulnerable-npm-dependency",
            "evidence_summary": f"{dep['name']}@{dep['version']} has {len(vulns)} OSV finding(s). Version match: {'exact' if dep['exact'] else 'range-derived'}.",
            "evidence": {
                "package": dep["name"],
                "version": dep["version"],
                "exact": dep["exact"],
                "osv_ids": [vuln.get("id") for vuln in vulns if vuln.get("id")],
            },
        })
    return findings, None


def _check_osv_many(extensions: list[Any]) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, str]]]:
    entries_by_extension: dict[str, list[dict[str, Any]]] = {}
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for extension in extensions:
        entries = [
            {"name": name, "version": _normalize_version(version), "exact": bool(re.match(r"^\d+\.\d+\.\d+", str(version)))}
            for name, version in extension.dependencies.items()
            if isinstance(version, str)
        ]
        entries = [entry for entry in entries if entry["version"]]
        entries_by_extension[extension.extension_id] = entries
        for entry in entries:
            unique.setdefault((entry["name"], entry["version"]), entry)
    if not unique:
        return {}, []

    keys = list(unique)
    vulns_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    errors: list[dict[str, str]] = []
    for index in range(0, len(keys), OSV_BATCH_SIZE):
        chunk = keys[index:index + OSV_BATCH_SIZE]
        body = json.dumps({
            "queries": [
                {"package": {"name": name, "ecosystem": "npm"}, "version": version}
                for name, version in chunk
            ]
        }).encode("utf-8")
        try:
            data = _http_post_json("https://api.osv.dev/v1/querybatch", body, timeout=15)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            errors.append({"source": "osv", "message": str(exc)})
            continue
        for offset, result in enumerate(data.get("results", [])):
            if index + offset >= len(keys):
                break
            vulns_by_key[keys[index + offset]] = result.get("vulns", [])

    findings_by_extension: dict[str, list[dict[str, Any]]] = {}
    for extension in extensions:
        extension_findings: list[dict[str, Any]] = []
        for dep in entries_by_extension.get(extension.extension_id, []):
            vulns = vulns_by_key.get((dep["name"], dep["version"]), [])
            if not vulns:
                continue
            malicious = any(str(vuln.get("id", "")).startswith("MAL-") for vuln in vulns)
            extension_findings.append({
                "extension_id": extension.extension_id,
                "severity": "CRITICAL" if malicious else "HIGH" if dep["exact"] else "MEDIUM",
                "confidence": 0.94 if malicious else 0.82 if dep["exact"] else 0.58,
                "category": "dependency",
                "rule_id": "malicious-npm-dependency" if malicious else "vulnerable-npm-dependency",
                "evidence_summary": f"{dep['name']}@{dep['version']} has {len(vulns)} OSV finding(s). Version match: {'exact' if dep['exact'] else 'range-derived'}.",
                "evidence": {
                    "package": dep["name"],
                    "version": dep["version"],
                    "exact": dep["exact"],
                    "osv_ids": [vuln.get("id") for vuln in vulns if vuln.get("id")],
                },
            })
        if extension_findings:
            findings_by_extension[extension.extension_id] = extension_findings
    return findings_by_extension, errors


def _fetch_marketplace_metadata_many(extension_ids: list[str]) -> tuple[dict[str, dict[str, Any] | None], list[dict[str, str]]]:
    unique_ids = list(dict.fromkeys(extension_ids))
    out: dict[str, dict[str, Any] | None] = {}
    errors: list[dict[str, str]] = []
    for index in range(0, len(unique_ids), MARKETPLACE_BATCH_SIZE):
        chunk = unique_ids[index:index + MARKETPLACE_BATCH_SIZE]
        body = json.dumps({
            "filters": [
                {
                    "criteria": [{"filterType": 7, "value": extension_id}],
                    "pageNumber": 1,
                    "pageSize": 1,
                }
                for extension_id in chunk
            ],
            "flags": 914,
        }).encode("utf-8")
        try:
            data = _http_post_json(MARKETPLACE_EXTENSIONQUERY_URL, body, timeout=15)
            results = data.get("results", [])
            for offset, extension_id in enumerate(chunk):
                result = results[offset] if offset < len(results) and isinstance(results[offset], dict) else {}
                extensions = result.get("extensions", []) if isinstance(result, dict) else []
                if extensions:
                    out[extension_id] = _normalize_marketplace_extension(extension_id, extensions[0])
                else:
                    out[extension_id] = {"extension_id": extension_id, "found": False}
        except (OSError, urllib.error.URLError, json.JSONDecodeError, AttributeError, IndexError) as exc:
            errors.append({"source": "marketplace", "message": str(exc), "extension_ids": ",".join(chunk)})
            for extension_id in chunk:
                metadata, error = _fetch_marketplace_metadata(extension_id)
                out[extension_id] = metadata
                if error:
                    errors.append({"source": "marketplace", "extension_id": extension_id, "message": error})
    return out, errors


def _fetch_marketplace_metadata(extension_id: str) -> tuple[dict[str, Any] | None, str | None]:
    body = json.dumps({
        "filters": [{
            "criteria": [{"filterType": 7, "value": extension_id}],
            "pageNumber": 1,
            "pageSize": 1,
        }],
        "flags": 914,
    }).encode("utf-8")
    try:
        data = _http_post_json(MARKETPLACE_EXTENSIONQUERY_URL, body, timeout=15)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return None, str(exc)
    try:
        extensions = data.get("results", [{}])[0].get("extensions", [])
    except (AttributeError, IndexError):
        return None, "Unexpected marketplace metadata response shape."
    if not extensions:
        return {"extension_id": extension_id, "found": False}, None
    return _normalize_marketplace_extension(extension_id, extensions[0]), None


def _fetch_openvsx_metadata(extension_id: str) -> tuple[dict[str, Any] | None, str | None]:
    publisher, name = extension_id.split(".", 1)
    try:
        raw = json.loads(_http_get_text(f"{OPENVSX_API_URL}/{publisher}/{name}", timeout=15))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"extension_id": extension_id, "found": False}, None
        return None, str(exc)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return None, str(exc)
    files = raw.get("files") if isinstance(raw.get("files"), dict) else {}
    return {
        "extension_id": extension_id,
        "found": True,
        "publisher": raw.get("namespace") or publisher,
        "publisher_display_name": raw.get("namespaceDisplayName") or raw.get("namespace") or publisher,
        "publisher_verified": bool(raw.get("verified")),
        "display_name": raw.get("displayName") or name,
        "extension_name": raw.get("name") or name,
        "version": raw.get("version") or "",
        "last_updated": raw.get("timestamp") or "",
        "install_count": int(raw.get("downloadCount") or 0),
        "rating_average": float(raw.get("averageRating") or 0),
        "rating_count": int(raw.get("reviewCount") or 0),
        "download_url": files.get("download") or "",
        "registry": "openvsx",
    }, None


def _fetch_repository_metadata_many(repo_urls: list[str]) -> tuple[dict[str, dict[str, Any] | None], list[dict[str, str]]]:
    unique = [url for url in dict.fromkeys(repo_urls) if url]
    out: dict[str, dict[str, Any] | None] = {}
    errors: list[dict[str, str]] = []
    for repo_url in unique:
        github = _github_repo_api_url(repo_url)
        if not github:
            out[repo_url] = None
            continue
        try:
            data = json.loads(_http_get_text(github, timeout=10))
            out[repo_url] = {
                "repository": repo_url,
                "found": True,
                "host": "github",
                "full_name": data.get("full_name") or "",
                "archived": bool(data.get("archived")),
                "disabled": bool(data.get("disabled")),
                "pushed_at": data.get("pushed_at") or "",
                "updated_at": data.get("updated_at") or "",
                "stargazers_count": int(data.get("stargazers_count") or 0),
                "fork": bool(data.get("fork")),
                "default_branch": data.get("default_branch") or "",
            }
        except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
            out[repo_url] = None
            errors.append({"source": "repository", "repository": repo_url, "message": str(exc)})
    return out, errors


def _github_repo_api_url(repo_url: str) -> str:
    raw = repo_url.strip()
    if raw.startswith("git+"):
        raw = raw[4:]
    raw = raw.removesuffix(".git")
    if raw.startswith("git@github.com:"):
        path = raw.split(":", 1)[1]
    else:
        parsed = urlparse(raw)
        if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
            return ""
        path = parsed.path.strip("/")
    parts = [part for part in path.split("/") if part]
    if len(parts) < 2:
        return ""
    return f"https://api.github.com/repos/{parts[0]}/{parts[1]}"


def _normalize_marketplace_extension(extension_id: str, raw: dict[str, Any]) -> dict[str, Any]:
    publisher = raw.get("publisher") if isinstance(raw.get("publisher"), dict) else {}
    versions = raw.get("versions") if isinstance(raw.get("versions"), list) else []
    latest_version = versions[0] if versions and isinstance(versions[0], dict) else {}
    stats = _marketplace_stats(raw.get("statistics"))
    metadata = {
        "extension_id": extension_id,
        "found": True,
        "publisher": publisher.get("publisherName") or "",
        "publisher_display_name": publisher.get("displayName") or "",
        "publisher_verified": _marketplace_publisher_verified(publisher),
        "display_name": raw.get("displayName") or "",
        "extension_name": raw.get("extensionName") or "",
        "version": latest_version.get("version") or "",
        "last_updated": latest_version.get("lastUpdated") or raw.get("lastUpdated") or "",
        "install_count": int(stats.get("install") or stats.get("installs") or 0),
        "rating_average": float(stats.get("averagerating") or stats.get("averageRating") or 0),
        "rating_count": int(stats.get("ratingcount") or stats.get("ratingCount") or 0),
        "registry": "vs-marketplace",
    }
    return metadata


def _marketplace_publisher_verified(publisher: dict[str, Any]) -> bool:
    flags = str(publisher.get("flags") or "").lower().split()
    return bool(
        publisher.get("isDomainVerified")
        or publisher.get("isVerified")
        or publisher.get("verified")
        or "verified" in flags
    )


def _marketplace_stats(raw_stats: Any) -> dict[str, float]:
    stats: dict[str, float] = {}
    if not isinstance(raw_stats, list):
        return stats
    for item in raw_stats:
        if not isinstance(item, dict):
            continue
        name = str(item.get("statisticName") or "").strip()
        if not name:
            continue
        try:
            stats[name] = float(item.get("value") or 0)
        except (TypeError, ValueError):
            continue
    return stats


def _marketplace_metadata_findings(extension_id: str, metadata: dict[str, Any] | None) -> list[dict[str, Any]]:
    if metadata is None:
        return []
    if not metadata.get("found"):
        return [_registry_finding(
            extension_id,
            "LOW",
            0.42,
            "reputation",
            "marketplace-extension-not-found",
            "Extension was not found in the VS Marketplace metadata query.",
            metadata,
        )]

    findings: list[dict[str, Any]] = []
    if metadata.get("publisher_verified"):
        findings.append(_registry_finding(
            extension_id,
            "INFO",
            0.95,
            "reputation",
            "marketplace-verified-publisher",
            "Marketplace metadata reports a verified publisher.",
            metadata,
        ))
    else:
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.46,
            "reputation",
            "marketplace-unverified-publisher",
            "Marketplace metadata does not report a verified publisher.",
            metadata,
        ))

    install_count = int(metadata.get("install_count") or 0)
    if install_count and install_count < LOW_INSTALL_THRESHOLD:
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.44,
            "reputation",
            "marketplace-low-install-count",
            f"Marketplace install count is low: {install_count}.",
            metadata,
        ))

    rating_count = int(metadata.get("rating_count") or 0)
    rating_average = float(metadata.get("rating_average") or 0)
    if rating_count >= 5 and rating_average and rating_average < 2.5:
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.48,
            "reputation",
            "marketplace-low-rating",
            f"Marketplace rating is low: {rating_average:.2f} across {rating_count} ratings.",
            metadata,
        ))
    if (
        rating_count >= 5
        and rating_average
        and rating_average < 2.5
        and install_count >= HIGH_INSTALL_RATING_MISMATCH_THRESHOLD
    ):
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.5,
            "reputation",
            "install-rating-mismatch",
            f"Marketplace install count is high ({install_count}) but rating is low ({rating_average:.2f} across {rating_count} ratings).",
            metadata,
        ))

    days_since_update = _days_since_update(metadata.get("last_updated"))
    if days_since_update is not None and days_since_update > STALE_EXTENSION_DAYS:
        evidence = dict(metadata)
        evidence["days_since_update"] = days_since_update
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.5,
            "reputation",
            "marketplace-stale-extension",
            f"Marketplace metadata says the extension has not been updated for {days_since_update} days.",
            evidence,
        ))
    impersonation = _name_impersonation_evidence(metadata)
    if impersonation:
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.52,
            "reputation",
            "marketplace-name-impersonation",
            f"Marketplace name is similar to {impersonation['target_display']} from {impersonation['target_publisher']}.",
            impersonation,
        ))
    return findings


def _repository_metadata_findings(extension_id: str, metadata: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not metadata:
        return []
    evidence = dict(metadata)
    evidence["evidence_class"] = "reputation"
    findings: list[dict[str, Any]] = []
    if metadata.get("archived") or metadata.get("disabled"):
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.52,
            "reputation",
            "repo-archived",
            "Declared GitHub repository is archived or disabled.",
            evidence,
        ))
    days = _days_since_update(metadata.get("pushed_at") or metadata.get("updated_at"))
    if days is not None:
        if days > STALE_REPOSITORY_DAYS:
            stale_evidence = dict(evidence)
            stale_evidence["days_since_push"] = days
            findings.append(_registry_finding(
                extension_id,
                "LOW",
                0.48,
                "reputation",
                "repo-stale",
                f"Declared GitHub repository has not been pushed for {days} days.",
                stale_evidence,
            ))
        else:
            maintained = dict(evidence)
            maintained["days_since_push"] = days
            findings.append(_registry_finding(
                extension_id,
                "INFO",
                0.72,
                "reputation",
                "repo-maintained",
                f"Declared GitHub repository has recent activity within {days} days.",
                maintained,
            ))
    return findings


def _name_impersonation_evidence(metadata: dict[str, Any]) -> dict[str, Any] | None:
    publisher = str(metadata.get("publisher") or "").lower()
    extension_name = _normalize_name(metadata.get("extension_name"))
    display_name = _normalize_name(metadata.get("display_name"))
    install_count = int(metadata.get("install_count") or 0)
    for target_publisher, target_name, target_display in IMPERSONATION_TARGETS:
        if publisher == target_publisher:
            continue
        target_normalized = _normalize_name(target_name)
        display_normalized = _normalize_name(target_display)
        similarity = max(
            _similarity(extension_name, target_normalized),
            _similarity(display_name, display_normalized),
            _similarity(display_name, target_normalized),
        )
        if similarity >= 0.9 and install_count < 10000:
            evidence = dict(metadata)
            evidence.update({
                "target_publisher": target_publisher,
                "target_extension": target_name,
                "target_display": target_display,
                "similarity": round(similarity, 3),
                "evidence_class": "reputation",
            })
            return evidence
    return None


def _normalize_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()


def _registry_finding(
    extension_id: str,
    severity: str,
    confidence: float,
    category: str,
    rule_id: str,
    evidence_summary: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "extension_id": extension_id,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "rule_id": rule_id,
        "evidence_summary": evidence_summary,
        "evidence": evidence,
    }


def _days_since_update(value: Any) -> int | None:
    if not value:
        return None
    raw = str(value).strip().replace("Z", "+00:00")
    try:
        timestamp = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return (datetime.now(UTC) - timestamp.astimezone(UTC)).days


def _normalize_version(range_value: str) -> str:
    value = str(range_value).strip()
    if value.startswith(("file:", "link:", "workspace:")):
        return ""
    match = re.search(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?|\d+\.\d+", value)
    return match.group(0) if match else ""


def _http_get_text(url: str, timeout: int) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError):
        return _curl(["curl", "-L", "--max-time", str(timeout), "-s", url])


def _http_post_json(url: str, body: bytes, timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError):
        text = _curl([
            "curl",
            "-L",
            "--max-time",
            str(timeout),
            "-s",
            "-H",
            "content-type: application/json",
            "-d",
            body.decode("utf-8"),
            url,
        ])
        return json.loads(text)


def _curl(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.SubprocessError as exc:
        raise OSError(str(exc)) from exc
