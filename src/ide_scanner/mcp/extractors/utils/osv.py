"""OSVQueryPipeline — query OSV.dev for a single MCP package's known vulns.

Version-agnostic lookup: we don't know the installed version of the MCP
package, so we ask OSV for every advisory ever filed against it and surface
a trimmed shape.
"""

import logging
import urllib.parse
from enum import Enum
from typing import Literal, Optional

import httpx
from pydantic import BaseModel

from ...types import PackageSourceEnum
from ...package_parser import PackageParser

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_MAX_RETRIES = 2
OSV_MAX_PAGES = 10
PKG_REGISTRY_API_URLS = {
    "PyPI": "https://pypi.org/pypi/{name}/json",
    "npm": "https://registry.npmjs.org/{name}",
}

SUMMARY_MAX_LEN = 240
ADVISORY_URL_FALLBACK = "https://osv.dev/vulnerability/{id}"

# PackageSourceEnum -> OSV ecosystem name. Docker / MISC have no OSV-queryable
# ecosystem, so they're intentionally absent: the pipeline will return
# queryable=False and the runner will SKIP.
SOURCE_TO_ECOSYSTEM = {
    PackageSourceEnum.NPX: "npm",
    PackageSourceEnum.UVX: "PyPI",
    PackageSourceEnum.PIPX: "PyPI",
}


class MCPVulnSeverityEnum(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MCPVulnDetail(BaseModel):
    """Single advisory surfaced from OSV, trimmed for FE consumption."""

    id: str
    aliases: list[str]
    severity: MCPVulnSeverityEnum
    summary: Optional[str]
    affected_range: Optional[str]
    advisory_url: Optional[str]
    cwe_ids: list[str]
    affects_latest_version: bool = False


class MCPVulnResult(BaseModel):
    """Aggregated OSV results for the MCP package itself.

    ``queryable`` distinguishes "we asked OSV and got no vulns" (queryable=True,
    vulns=[]) from "we couldn't form a query" (queryable=False, e.g. docker
    images or unknown ecosystems). The runner uses this to SKIP rather than
    score 0 for non-queryable MCPs.
    """

    success: bool
    error_message: Optional[str] = None
    queryable: bool
    ecosystem: Optional[Literal["npm", "PyPI"]] = None
    package_name: Optional[str] = None
    latest_version: Optional[str] = None
    contains_cve: bool
    vulns: list[MCPVulnDetail]


class OSVQueryPipeline:
    """Resolves MCP install command -> OSV query -> shaped vuln list."""

    _parser = PackageParser()

    @classmethod
    async def query(
        cls,
        install_command: Optional[str] = None,
        repo_url: Optional[str] = None,
    ) -> MCPVulnResult:
        """Query OSV for vulns affecting the MCP package. Never raises."""
        try:
            pkg_name, ecosystem = cls._resolve_package(install_command, repo_url)

            if not (pkg_name and ecosystem) and not repo_url:
                return MCPVulnResult(
                    success=True,
                    queryable=False,
                    ecosystem=ecosystem,
                    package_name=pkg_name,
                    latest_version=None,
                    contains_cve=False,
                    vulns=[],
                )

            raw_vulns: list[dict] = []
            latest_version: Optional[str] = None
            latest_vuln_keys = set()
            async with httpx.AsyncClient(timeout=10.0) as client:
                if pkg_name and ecosystem:
                    raw_vulns.extend(await cls._fetch(pkg_name, ecosystem, client=client))

                    try:
                        latest_version = await cls._fetch_latest_registry_version(pkg_name, ecosystem, client)
                        if latest_version:
                            latest_raw_vulns = await cls._fetch(
                                pkg_name, ecosystem, client=client, version=latest_version
                            )
                            latest_vuln_keys = cls._collect_vuln_keys(latest_raw_vulns)
                    except Exception as e:
                        logger.warning(f"Latest-version vuln enrichment failed for {ecosystem}:{pkg_name}: {str(e)}")

                if repo_url:
                    # repo_url is normalized in our catalog entries. so normalization is not required
                    raw_vulns.extend(
                        await cls._fetch(f"{repo_url.rstrip('/')}.git", "GIT", client=client)
                    )

            raw_vulns = cls._dedupe_vulns(raw_vulns)
            vulns = [
                cls._shape_vuln(v, bool(cls._collect_vuln_keys([v]) & latest_vuln_keys))
                for v in raw_vulns
            ]
            logger.info(f"MCP vuln OSV query pkg={ecosystem}:{pkg_name} git={repo_url} -> {len(vulns)} vuln(s)")
            return MCPVulnResult(
                success=True,
                queryable=True,
                ecosystem=ecosystem,
                package_name=pkg_name,
                latest_version=latest_version,
                contains_cve=bool(vulns),
                vulns=vulns,
            )
        except Exception as e:
            logger.warning(f"OSV query failed: {e}")
            return MCPVulnResult(
                success=False,
                error_message=f"OSV query failed: {e}",
                queryable=False,
                latest_version=None,
                contains_cve=False,
                vulns=[],
            )

    @staticmethod
    def _dedupe_vulns(raw_vulns: list[dict]) -> list[dict]:
        """Dedupe raw OSV vulns by id + aliases across multiple query sources."""
        seen: set[str] = set()
        out: list[dict] = []
        for v in raw_vulns:
            ids = {v.get("id") or ""} | {a for a in (v.get("aliases") or []) if a}
            ids.discard("")
            if ids & seen:
                continue
            seen |= ids
            out.append(v)
        return out

    @staticmethod
    def _collect_vuln_keys(raw_vulns: list[dict]) -> set[str]:
        """Collect stable vuln identifiers (OSV ids + aliases) for matching."""
        keys: set[str] = set()
        for vuln in raw_vulns:
            vid = vuln.get("id")
            if vid:
                keys.add(vid)
            keys.update(alias for alias in (vuln.get("aliases") or []) if alias)
        return keys

    # ========== Package -> OSV target ==========

    @classmethod
    def _resolve_package(
        cls, install_command: Optional[str], repo_url: Optional[str]
    ) -> tuple[Optional[str], Optional[str]]:
        """Parse the install command into (package_name, osv_ecosystem).

        Returns (None, None) for docker / MISC / unparseable inputs.
        """
        if not install_command:
            return None, None
        try:
            result = cls._parser.parse(install_command, repo_url=repo_url)
        except Exception as e:
            logger.debug(f"PackageParser failed on {install_command!r}: {e}")
            return None, None

        ecosystem = SOURCE_TO_ECOSYSTEM.get(result.source)
        if not ecosystem:
            return None, None

        # PackageParser prefixes names like "npx/@scope/pkg" or "uvx/pkg"; strip
        # the single leading source prefix to recover the registry name
        raw_name = result.package_name
        prefix = f"{result.source.value}/"
        name = raw_name[len(prefix):] if raw_name.startswith(prefix) else raw_name
        return (name or None), ecosystem

    # ========== HTTP ==========

    @classmethod
    async def _fetch_latest_registry_version(
        cls,
        package_name: str,
        ecosystem: str,
        client: httpx.AsyncClient,
    ) -> Optional[str]:
        template = PKG_REGISTRY_API_URLS.get(ecosystem)
        if not template:
            return None

        encoded_name = urllib.parse.quote(package_name, safe="@/")
        resp = await client.get(template.format(name=encoded_name))
        resp.raise_for_status()
        data = resp.json()

        if ecosystem == "PyPI":
            return ((data.get("info") or {}).get("version") or "").strip() or None
        if ecosystem == "npm":
            return ((data.get("dist-tags") or {}).get("latest") or "").strip() or None
        return None

    @classmethod
    async def _fetch(
        cls,
        name: str,
        ecosystem: str,
        client: httpx.AsyncClient,
        version: Optional[str] = None,
    ) -> list[dict]:
        payload = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            payload["version"] = version
        all_vulns: list[dict] = []
        page_token: Optional[str] = None
        seen_page_tokens: set[str] = set()

        for _ in range(OSV_MAX_PAGES):
            page_payload = payload.copy()
            if page_token:
                page_payload["page_token"] = page_token

            last_err = None
            page_data: Optional[dict] = None
            for attempt in range(OSV_MAX_RETRIES + 1):
                try:
                    resp = await client.post(OSV_API_URL, json=page_payload)
                    if resp.status_code >= 500 and attempt < OSV_MAX_RETRIES:
                        continue
                    resp.raise_for_status()
                    page_data = resp.json()
                    break
                except (httpx.TimeoutException, httpx.TransportError) as e:
                    last_err = e
                    if attempt >= OSV_MAX_RETRIES:
                        break

            if page_data is None:
                if last_err:
                    raise last_err
                return all_vulns

            all_vulns.extend(page_data.get("vulns", []) or [])

            next_page_token = page_data.get("next_page_token")
            if not next_page_token:
                return all_vulns
            if next_page_token in seen_page_tokens:
                return all_vulns

            seen_page_tokens.add(next_page_token)
            page_token = next_page_token

        logger.debug(f"OSV pagination hit page limit for {ecosystem}:{name} after {OSV_MAX_PAGES} pages")
        return all_vulns

    # ========== Shape raw OSV vuln -> trimmed detail ==========

    @classmethod
    def _shape_vuln(
        cls, raw: dict, affects_latest_version: bool = False
    ) -> MCPVulnDetail:
        vid = raw.get("id") or ""
        db_specific = raw.get("database_specific") or {}
        affected_range = cls._resolve_range(raw.get("affected") or [])

        # we get severity from database_specific.severity just like in utils/sca.py because the outer severity
        # is seldom/not populated
        severity_raw = db_specific.get("severity")
        normalized_severity = severity_raw.upper() if isinstance(severity_raw, str) else None
        if normalized_severity in {"CRITICAL", "HIGH"}:
            severity = MCPVulnSeverityEnum.HIGH
        elif normalized_severity in {"MODERATE", "MEDIUM"}:
            severity = MCPVulnSeverityEnum.MEDIUM
        else:
            severity = MCPVulnSeverityEnum.LOW

        summary_raw = (raw.get("summary") or "").strip()
        if not summary_raw:
            summary = None
        elif len(summary_raw) <= SUMMARY_MAX_LEN:
            summary = summary_raw
        else:
            summary = summary_raw[: SUMMARY_MAX_LEN - 1].rstrip() + "…"

        advisory_url: Optional[str] = None
        for r in raw.get("references") or []:
            if isinstance(r, dict) and r.get("type") == "ADVISORY" and r.get("url"):
                advisory_url = r["url"]
                break
        if not advisory_url and vid:
            advisory_url = ADVISORY_URL_FALLBACK.format(id=vid)

        return MCPVulnDetail(
            id=vid,
            aliases=[a for a in (raw.get("aliases") or []) if a],
            severity=severity,
            summary=summary,
            affected_range=affected_range or None,
            advisory_url=advisory_url,
            cwe_ids=[c for c in (db_specific.get("cwe_ids") or []) if c],
            affects_latest_version=affects_latest_version,
        )

    @staticmethod
    def _resolve_range(affected: list[dict]) -> str:
        """Render a human-readable affected version range."""
        parts: list[str] = []
        for a in affected:
            for r in a.get("ranges") or []:
                introduced: Optional[str] = None
                for ev in r.get("events") or []:
                    if "introduced" in ev:
                        introduced = ev["introduced"]

                    end: Optional[str] = None
                    inclusive_end = False
                    if "fixed" in ev:
                        end = ev["fixed"]
                    elif "last_affected" in ev:
                        end = ev["last_affected"]
                        inclusive_end = True

                    if not end:
                        continue

                    seg = f"<= {end}" if inclusive_end else f"< {end}"
                    if introduced and introduced != "0":
                        seg = f">= {introduced}, {seg}"
                    parts.append(seg)
                    introduced = None
        seen = set()
        unique_parts = [p for p in parts if not (p in seen or seen.add(p))]
        return " || ".join(unique_parts)


__all__ = [
    "OSVQueryPipeline",
    "MCPVulnResult",
    "MCPVulnDetail",
    "MCPVulnSeverityEnum",
]

