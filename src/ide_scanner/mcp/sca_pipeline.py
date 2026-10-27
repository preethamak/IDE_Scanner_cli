"""SCAPipeline — full SCA scanning pipeline with lockfile generation, parsing, and scanner execution."""

import asyncio
import glob
import json
import logging
import os
import re
from enum import Enum
from pathlib import Path
from typing import Optional

from packageurl import PackageURL
from pydantic import BaseModel

from .sca_support import find_matching_files, run_subprocess_exec
from .lockfiles import (
    LOCKFILE_GENERATORS,
    LOCKFILE_PARSERS,
    generate_lockfile,
    parse_lockfile,
)

logger = logging.getLogger(__name__)


# Dependency manifest / lockfile basenames the SCA pipeline can scan. Scoped to the
# ecosystems we support end-to-end (lockfile generators + parsers + depscan project
# types): Python, JS/Node, Go, Rust.
SCA_SUPPORTED_FILES: frozenset[str] = frozenset({
    # Python
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "Pipfile", "Pipfile.lock", "poetry.lock", "pdm.lock", "uv.lock",
    # JavaScript / TypeScript
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lock", "npm-shrinkwrap.json",
    # Go
    "go.mod", "go.sum",
    # Rust
    "Cargo.toml", "Cargo.lock",
})


class ScannerSourceEnum(Enum):
    DEPSCAN = "depscan"
    OSV = "osv"
    DATADOG = "datadog"


class VulnDetails(BaseModel):
    """Details about a specific vulnerability."""

    scanner_source: ScannerSourceEnum
    id: str
    transitive: bool
    reachable: bool
    exploitable: bool
    used_in_num_locations: int
    severity: Optional[str]
    raw_details: dict


class PURLVulnsModel(BaseModel):
    """Vulnerability information for a specific package (PURL)."""

    ecosystem: str
    name: str
    versions: list[str]
    purl: Optional[str] = None
    contains_cve: bool
    contains_malware: bool
    cve_details: list[VulnDetails]
    malware_details: list[VulnDetails]


class ScannerResultModel(BaseModel):
    """Result from running a scanner subprocess."""

    stdout: Optional[bytes] = None
    stderr: Optional[bytes] = None
    returncode: Optional[int] = None
    error_msg: Optional[str] = None


class SCAScanResult(BaseModel):
    """Result from running SCA scans."""

    success: bool
    error_message: Optional[str] = None
    dependencies: list[dict]
    purl_vulns: list[PURLVulnsModel]


class SCAPipeline:
    """Orchestrates the full SCA scanning pipeline."""

    @classmethod
    async def scan(cls, repo_path: str) -> SCAScanResult:
        """Run SCA scans and return structured results. Never throws."""

        try:
            return await cls._scan_internal(repo_path)
        except Exception as e:
            logger.warning(f"SCA scan failed with unexpected error: {e}")
            return SCAScanResult(
                success=False,
                error_message=f"SCA scan failed: {str(e)}",
                dependencies=[],
                purl_vulns=[],
            )

    @classmethod
    async def _scan_internal(cls, repo_path: str) -> SCAScanResult:

        dependencies, _direct_dep_names, transitive_dep_names = (
            await cls._collect_dependencies_from_lockfiles(repo_path)
        )

        depscan_task = asyncio.create_task(cls._run_depscan(repo_path))
        osv_task = asyncio.create_task(cls._run_osv(repo_path))
        depscan_result, osv_result = await asyncio.gather(depscan_task, osv_task)

        error_messages = []
        if depscan_result.error_msg:
            error_messages.append(depscan_result.error_msg)
        if osv_result.error_msg:
            error_messages.append(osv_result.error_msg)

        if depscan_result.error_msg and osv_result.error_msg:
            return SCAScanResult(
                success=False,
                error_message="Unable to scan dependencies: " + " ".join(error_messages),
                dependencies=dependencies,
                purl_vulns=[],
            )

        if depscan_result.returncode != 0:
            logger.warning("OWASP Depscan Scanner failed")
            logger.warning(
                f"OWASP Depscan Scanner returned {depscan_result.returncode} with stdout/stderr: {depscan_result.stdout} \n\n{depscan_result.stderr}")
            error_messages.append(
                f"OWASP Depscan Scanner exited with code {depscan_result.returncode}."
            )

        if osv_result.returncode == 128:
            error_messages.append("OSV Scanner didn't find any package manifests to scan.")

        if not osv_result.stdout or not osv_result.stdout.strip():
            logger.warning("OSV Scanner produced no output")
            error_messages.append("OSV Scanner produced no output.")

        if depscan_result.returncode != 0 and (
            not osv_result.stdout or not osv_result.stdout.strip()
        ):
            return SCAScanResult(
                success=False,
                error_message="Unable to scan dependencies: " + " ".join(error_messages),
                dependencies=dependencies,
                purl_vulns=[],
            )

        depscan_map: dict[tuple[str, str], dict] = {}
        if depscan_result.returncode == 0:
            depscan_map = await cls._process_depscan(repo_path)

        osv_result_json = None
        try:
            if osv_result.stdout is not None and (
                osv_stdout := osv_result.stdout.decode("utf-8")
            ):
                osv_result_json = json.loads(osv_stdout)
        except Exception as e:
            logger.warning(f"OSV Scanner produced invalid JSON output - {e}")
            error_messages.append("OSV Scanner produced invalid JSON output.")
            if depscan_result.returncode != 0:
                return SCAScanResult(
                    success=False,
                    error_message="Unable to scan dependencies: " + " ".join(error_messages),
                    dependencies=dependencies,
                    purl_vulns=[],
                )

        all_vulns = await cls._process_osv(
            repo_path, osv_result_json, depscan_map, transitive_dep_names
        )

        return SCAScanResult(
            success=True,
            error_message=" ".join(error_messages) if error_messages else None,
            dependencies=dependencies,
            purl_vulns=all_vulns,
        )

    # ========== Datadog malicious-package lookup ==========

    @staticmethod
    def load_datadog_manifests(datadog_malicious_home: str) -> dict[str, dict]:
        """Load Datadog malicious package manifests (npm.json, pypi.json) from a dir."""
        manifests: dict[str, dict] = {}
        for ecosystem in ("npm", "pypi"):
            file_path = f"{datadog_malicious_home}/{ecosystem}.json"
            try:
                with open(file_path, "r") as f:
                    manifests[ecosystem] = json.loads(f.read())
            except Exception:
                continue
        return manifests

    @staticmethod
    def merge_datadog_malicious(
        purl_vulns: list[PURLVulnsModel],
        dependencies: list[dict],
        manifests: dict[str, dict],
    ) -> list[PURLVulnsModel]:
        """Cross-reference deps against Datadog malicious manifests, appending a
        malware PURL entry (scanner_source=datadog) for each match not already
        flagged as malware by a scanner. Datadog covers npm/pypi only."""
        if not manifests:
            return purl_vulns

        # Track packages already flagged as malware by the scanners.
        scanner_pkg_keys: set[tuple[str, str, str]] = set()
        for pv in purl_vulns:
            if pv.contains_malware:
                for version in pv.versions:
                    scanner_pkg_keys.add((pv.ecosystem.lower(), pv.name.lower(), version))

        datadog_vulns: list[PURLVulnsModel] = []
        for dep in dependencies:
            ecosystem = dep.get("ecosystem")
            if ecosystem not in ("npm", "pypi"):
                continue

            name = dep.get("name", "").lower()
            version = dep.get("version")
            manifest = manifests.get(ecosystem, {})
            if name not in manifest:
                continue

            # Skip if a scanner already flagged this exact version as malware.
            if version and (ecosystem.lower(), name, version) in scanner_pkg_keys:
                continue

            dd_info = manifest[name]
            versions = [version] if version else []
            datadog_vulns.append(
                PURLVulnsModel(
                    ecosystem=ecosystem,
                    name=name,
                    versions=versions,
                    purl=f"pkg:{ecosystem}/{name}@{version}" if version else f"pkg:{ecosystem}/{name}",
                    contains_cve=False,
                    contains_malware=True,
                    cve_details=[],
                    malware_details=[
                        VulnDetails(
                            scanner_source=ScannerSourceEnum.DATADOG,
                            id=f"DATADOG-MAL-{ecosystem}-{name}",
                            transitive=False,
                            reachable=False,
                            exploitable=False,
                            used_in_num_locations=0,
                            severity="HIGH",
                            raw_details=dd_info if isinstance(dd_info, dict) else {"name": name},
                        )
                    ],
                )
            )

        return purl_vulns + datadog_vulns

    # ========== Dependency Collection ==========

    @classmethod
    async def _collect_dependencies_from_lockfiles(
        cls, repo_path: str
    ) -> tuple[
        list[dict],
        set[tuple[Optional[str], str]],
        set[tuple[Optional[str], str]],
    ]:
        manifests = find_matching_files(repo_path, list(LOCKFILE_GENERATORS.keys()))
        generated_results = await asyncio.gather(
            *[generate_lockfile(m) for m in manifests], return_exceptions=True
        )
        generated_lockfiles = [
            str(result)
            for result in generated_results
            if result is not None and isinstance(result, Path)
        ]

        existing_lockfiles = find_matching_files(repo_path, list(LOCKFILE_PARSERS.keys()))
        all_lockfiles = list(set(generated_lockfiles + existing_lockfiles))
        if not all_lockfiles:
            return cls._parse_manifests_directly(manifests)

        parsed_results = await asyncio.gather(
            *[parse_lockfile(lockfile) for lockfile in all_lockfiles]
        )
        direct_deps: set[tuple[Optional[str], str]] = set()
        transitive_deps: set[tuple[Optional[str], str]] = set()

        for parsed_lockfile in parsed_results:
            ecosystem = parsed_lockfile.ecosystem
            direct_deps.update((ecosystem, name) for name in parsed_lockfile.direct)
            transitive_deps.update((ecosystem, name) for name in parsed_lockfile.transitive)

        transitive_deps -= direct_deps

        dependency_map: dict[tuple[Optional[str], str, Optional[str]], dict] = {}
        entries_by_name_type: dict[
            tuple[Optional[str], str, str],
            set[tuple[Optional[str], str, Optional[str]]],
        ] = {}
        exact_entries: set[tuple[Optional[str], str, str]] = set()

        for parsed_lockfile in parsed_results:
            ecosystem = parsed_lockfile.ecosystem
            if parsed_lockfile.transitive_entries:
                for entry in parsed_lockfile.transitive_entries:
                    dep_type = (
                        "direct"
                        if (ecosystem, entry.name) in direct_deps
                        else "transitive"
                    )
                    cls._upsert_dependency(
                        dependency_map, entries_by_name_type, exact_entries,
                        entry.name, entry.version, dep_type, ecosystem,
                    )
            if parsed_lockfile.direct_entries:
                for entry in parsed_lockfile.direct_entries:
                    cls._upsert_dependency(
                        dependency_map, entries_by_name_type, exact_entries,
                        entry.name, entry.version, "direct", ecosystem,
                    )

        manifest_deps, manifest_direct, _ = cls._parse_manifests_directly(manifests)
        for dep in manifest_deps:
            name = dep.get("name")
            version = dep.get("version")
            ecosystem = dep.get("ecosystem")
            if not name:
                continue
            cls._upsert_dependency(
                dependency_map, entries_by_name_type, exact_entries,
                name, version, "direct", ecosystem,
            )
        direct_deps.update(manifest_direct)

        dependencies = sorted(
            dependency_map.values(),
            key=lambda d: (
                0 if d["dependency_type"] == "direct" else 1,
                d.get("ecosystem") or "",
                d["name"],
                d["version"] or "",
            ),
        )
        return dependencies, direct_deps, transitive_deps

    @classmethod
    def _parse_manifests_directly(
        cls, manifests: list[str]
    ) -> tuple[
        list[dict],
        set[tuple[Optional[str], str]],
        set[tuple[Optional[str], str]],
    ]:
        import tomllib

        dependencies: list[dict] = []
        direct_deps: set[tuple[Optional[str], str]] = set()

        ecosystem_map = {"package.json": "npm", "pyproject.toml": "pypi"}

        for manifest_path in manifests:
            filename = Path(manifest_path).name
            ecosystem = ecosystem_map.get(filename)
            if not ecosystem:
                continue

            try:
                if filename == "package.json":
                    with open(manifest_path, "r") as f:
                        data = json.load(f)
                    for section in ("dependencies", "devDependencies"):
                        for name, version_spec in data.get(section, {}).items():
                            direct_deps.add((ecosystem, name))
                            version = (
                                version_spec.lstrip("^~>=<")
                                if isinstance(version_spec, str)
                                else None
                            )
                            dependencies.append({
                                "name": name, "version": version,
                                "dependency_type": "direct", "ecosystem": ecosystem,
                            })
                elif filename == "pyproject.toml":
                    with open(manifest_path, "rb") as f:
                        data = tomllib.load(f)
                    project_deps = data.get("project", {}).get("dependencies", [])
                    for dep_str in project_deps:
                        if isinstance(dep_str, str):
                            parts = re.split(r"[<>=!~\[\]]", dep_str, maxsplit=1)
                            name = parts[0].strip()
                            version = parts[1].strip().split(",")[0] if len(parts) > 1 else None
                            direct_deps.add((ecosystem, name))
                            dependencies.append({
                                "name": name, "version": version,
                                "dependency_type": "direct", "ecosystem": ecosystem,
                            })
            except Exception as e:
                logger.warning(f"Failed to parse manifest {manifest_path}: {e}")
                continue

        return dependencies, direct_deps, set()

    @classmethod
    def _upsert_dependency(
        cls,
        dependency_map: dict[tuple[Optional[str], str, Optional[str]], dict],
        entries_by_name_type: dict[
            tuple[Optional[str], str, str],
            set[tuple[Optional[str], str, Optional[str]]],
        ],
        exact_entries: set[tuple[Optional[str], str, str]],
        name: Optional[str],
        version: Optional[str],
        dep_type: str,
        ecosystem: Optional[str] = None,
    ) -> None:
        if not name:
            return
        key = (ecosystem, name, version)
        name_type_key = (ecosystem, name, dep_type)
        is_range_version = cls._is_range_version(version)
        entry_keys = entries_by_name_type.setdefault(name_type_key, set())

        if not is_range_version:
            for existing_key in list(entry_keys):
                existing_version = existing_key[2]
                if cls._is_range_version(existing_version):
                    dependency_map.pop(existing_key, None)
                    entry_keys.discard(existing_key)

        if is_range_version and name_type_key in exact_entries:
            return

        existing = dependency_map.get(key)
        if existing:
            if dep_type == "direct" and existing["dependency_type"] != "direct":
                existing["dependency_type"] = "direct"
            return

        dependency_map[key] = {
            "name": name, "version": version,
            "dependency_type": dep_type, "ecosystem": ecosystem,
        }
        entry_keys.add(key)
        if not is_range_version:
            exact_entries.add(name_type_key)

    @staticmethod
    def _is_range_version(version: Optional[str]) -> bool:
        if version is None or version == "":
            return True
        range_indicators = ("^", "~", "*", ">", "<", "=", "||")
        if any(indicator in version for indicator in range_indicators):
            return True
        if version.endswith(".x") or version.endswith(".X"):
            return True
        return False

    # ========== Depscan Processing ==========

    @classmethod
    async def _run_depscan(cls, repo_path: str) -> ScannerResultModel:

        timeout = 300
        args = [
            "depscan", "--src", ".", "-t", "nodejs,py,java,go,rust",
            "--technique", "manifest-analysis",
            "--reports-dir", "./reports/", "--profile", "research",
            "--explain", "--bom-engine", "CdxgenGenerator",  # "--bom-dir", "./reports/",
        ]
        try:
            stdout, stderr, returncode = await run_subprocess_exec(
                args=args, cwd=repo_path, timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"OWASP Depscan Scanner timed out after {timeout} seconds")
            return ScannerResultModel(
                error_msg=f"OWASP Depscan Scanner timed out after {timeout} seconds"
            )
        except Exception as e:
            logger.warning("OWASP Depscan Scanner process failed")
            return ScannerResultModel(error_msg=f"OWASP Depscan Scanner process failed: {str(e)}")
        return ScannerResultModel(stdout=stdout, stderr=stderr, returncode=returncode)

    @classmethod
    async def _process_depscan(cls, repo_path: str) -> dict[tuple[str, str], dict]:
        reports_path = repo_path.rstrip("/") + "/reports/"
        vdr_paths = await asyncio.to_thread(glob.glob, os.path.join(reports_path, "*.vdr.json"))
        package_map: dict[tuple[str, str], dict] = {}

        if vdr_paths:
            results = await asyncio.gather(*[cls._process_vdr(p) for p in vdr_paths])
            for res in results:
                cls._merge_package_maps(package_map, res)
        return package_map

    @classmethod
    async def _process_vdr(cls, vdr_path: str) -> dict[tuple[str, str], dict]:

        def read_and_parse():
            return json.loads(Path(vdr_path).read_text())

        vdr = await asyncio.to_thread(read_and_parse)
        package_map: dict[tuple[str, str], dict] = {}

        for vuln in vdr.get("vulnerabilities", []):
            bom_ref = vuln.get("bom-ref", "")
            parsed = cls._parse_depscan_purl(bom_ref)
            if not parsed:
                logger.warning(f"Depscan VDR has invalid PURL in bom-ref: {bom_ref}")
                continue
            ecosystem, name, version = parsed
            identifiers = cls._extract_vuln_identifiers(vuln)
            vuln_details = cls._get_depscan_vuln_details(vuln)
            cls._upsert_version_vuln(
                package_map, ecosystem, name, version, vuln_details, identifiers,
            )
        return package_map

    @classmethod
    def _get_depscan_vuln_details(cls, vuln: dict) -> VulnDetails:
        insights = []
        for prop in vuln.get("properties", []):
            if prop.get("name") == "depscan:insights":
                insights = prop.get("value", "").split("\n")
                break

        used_in_num_locations = 0
        for i in insights:
            match = re.match(r"Used in (\d+) locations", i)
            if match:
                used_in_num_locations = int(match.group(1))
                break

        severity = vuln.get("ratings", [{}])[0].get("severity", None)
        if severity is not None:
            severity = severity.upper()
        if vuln["id"].startswith("MAL-"):
            severity = "HIGH"

        return VulnDetails(
            scanner_source=ScannerSourceEnum.DEPSCAN,
            id=vuln["id"],
            transitive=any("indirect dependency" in i.lower() for i in insights),
            reachable=any("reachable" in i.lower() for i in insights),
            exploitable=any("exploit" in i.lower() for i in insights),
            used_in_num_locations=used_in_num_locations,
            severity=severity,
            raw_details={
                **vuln,
                "description": vuln.get("description") or vuln.get("summary", ""),
            },
        )

    # ========== OSV Processing ==========

    @classmethod
    async def _run_osv(cls, repo_path: str) -> ScannerResultModel:

        timeout = 90
        args = [
            "osv-scanner", "--format", "json", "-r",
            "--no-resolve", "--no-call-analysis=go", repo_path,
        ]
        try:
            stdout, stderr, returncode = await run_subprocess_exec(args=args, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"OSV Scanner timed out after {timeout} seconds")
            return ScannerResultModel(error_msg=f"OSV Scanner timed out after {timeout} seconds.")
        except Exception as e:
            logger.warning("OSV Scanner process failed")
            return ScannerResultModel(error_msg=f"OSV Scanner process failed: {str(e)}.")
        return ScannerResultModel(stdout=stdout, stderr=stderr, returncode=returncode)

    @classmethod
    async def _process_osv(
        cls,
        repo_path: str,
        osv_result: Optional[dict],
        depscan_map: dict[tuple[str, str], dict],
        transitive_dependencies: Optional[set[tuple[Optional[str], str]]] = None,
    ) -> list[PURLVulnsModel]:
        if not osv_result:
            return cls._build_purl_vulns_from_map(depscan_map)

        deduped_results = cls._dedupe_osv_vulnerabilities(osv_result)
        if transitive_dependencies is None:
            _, _, transitive_deps = await cls._collect_dependencies_from_lockfiles(repo_path)
        else:
            transitive_deps = transitive_dependencies

        for source in deduped_results.get("results", []):
            for package in source.get("packages", []):
                pkg_info = package.get("package", {})
                normalized = cls._normalize_osv_package_info(pkg_info)
                if not normalized:
                    continue
                ecosystem, name, version = normalized
                key = (ecosystem, name)

                package_entry = depscan_map.setdefault(
                    key, {"ecosystem": ecosystem, "name": name, "versions": {}},
                )
                version_bucket = package_entry["versions"].setdefault(
                    version, cls._init_version_bucket()
                )

                for vuln in package.get("vulnerabilities", []):
                    vid = vuln["id"]
                    identifiers = cls._extract_vuln_identifiers(vuln)
                    if identifiers & version_bucket["ids"]:
                        continue
                    version_bucket["ids"].update(identifiers)

                    severity = (
                        vuln.get("database_specific", {}).get("severity", "UNKNOWN").upper()
                    )
                    if vid.startswith("MAL-"):
                        severity = "HIGH"
                    transitive = (ecosystem, name) in transitive_deps
                    cls._add_vuln_to_bucket(
                        version_bucket,
                        VulnDetails(
                            scanner_source=ScannerSourceEnum.OSV,
                            id=vid,
                            transitive=transitive,
                            reachable=False,
                            exploitable=False,
                            used_in_num_locations=0,
                            severity=severity,
                            raw_details={
                                **vuln,
                                "description": vuln.get("description") or vuln.get("summary", ""),
                            },
                        ),
                    )
        return cls._build_purl_vulns_from_map(depscan_map)

    @classmethod
    def _dedupe_osv_vulnerabilities(cls, osv_result: dict) -> dict:
        package_map: dict[tuple[str, str, str], dict] = {}
        for source in osv_result.get("results", []):
            for package in source.get("packages", []):
                pkg_info = package.get("package", {})
                normalized = cls._normalize_osv_package_info(pkg_info)
                if not normalized:
                    continue
                ecosystem, name, version = normalized
                key = (ecosystem, name, version)
                if key not in package_map:
                    package_map[key] = {
                        "package": {"ecosystem": ecosystem, "name": name, "version": version},
                        "vulnerabilities": [],
                    }
                package_map[key]["vulnerabilities"].extend(package.get("vulnerabilities", []))

        for pkg_data in package_map.values():
            seen_ids = set()
            filtered_vulns = []
            for vuln in pkg_data["vulnerabilities"]:
                identifiers = cls._extract_vuln_identifiers(vuln)
                if identifiers & seen_ids:
                    seen_ids.update(identifiers)
                    continue
                seen_ids.update(identifiers)
                filtered_vulns.append(vuln)
            pkg_data["vulnerabilities"] = filtered_vulns

        return {"results": [{"packages": list(package_map.values())}] if package_map else []}

    # ========== Shared Helpers ==========

    @staticmethod
    def _normalize_package_name(namespace: Optional[str], name: Optional[str]) -> str:
        if not name:
            return ""
        if namespace:
            return f"{namespace}/{name}"
        return name

    @staticmethod
    def _build_purl(ecosystem: str, name: str, version: str) -> Optional[str]:
        if not ecosystem or not name:
            return None
        if version:
            return f"pkg:{ecosystem}/{name}@{version}"
        return f"pkg:{ecosystem}/{name}"

    @staticmethod
    def _add_vuln_to_bucket(bucket: dict, vuln_details: VulnDetails) -> None:
        if SCAPipeline._is_malware_vuln(vuln_details):
            bucket["contains_malware"] = True
            bucket["malware_details"].append(vuln_details)
        else:
            bucket["contains_cve"] = True
            bucket["cve_details"].append(vuln_details)

    @staticmethod
    def _severity_rank(severity: Optional[str]) -> int:
        severity_order = [
            None, "NONE", "UNKNOWN", "INFO", "LOW", "MEDIUM", "MODERATE", "HIGH", "CRITICAL",
        ]
        normalized = severity.upper() if isinstance(severity, str) else None
        try:
            return severity_order.index(normalized)
        except ValueError:
            return 0

    @classmethod
    def _merge_vuln_details(cls, existing: VulnDetails, incoming: VulnDetails) -> None:
        existing.transitive = existing.transitive and incoming.transitive
        existing.reachable = existing.reachable or incoming.reachable
        existing.exploitable = existing.exploitable or incoming.exploitable
        existing.used_in_num_locations = max(
            existing.used_in_num_locations, incoming.used_in_num_locations
        )
        if cls._severity_rank(incoming.severity) > cls._severity_rank(existing.severity):
            existing.severity = incoming.severity

    @classmethod
    def _merge_group_vuln_details(cls, group: dict, vuln_details: VulnDetails) -> None:
        if cls._is_malware_vuln(vuln_details):
            target_list = group["malware_details"]
        else:
            target_list = group["cve_details"]
        if target_list:
            cls._merge_vuln_details(target_list[0], vuln_details)
        else:
            cls._add_vuln_to_bucket(group, vuln_details)

    @staticmethod
    def _init_version_bucket() -> dict:
        return {
            "ids": set(),
            "contains_cve": False,
            "contains_malware": False,
            "cve_details": [],
            "malware_details": [],
        }

    @classmethod
    def _upsert_version_vuln(
        cls,
        package_map: dict[tuple[str, str], dict],
        ecosystem: str,
        name: str,
        version: str,
        vuln_details: VulnDetails,
        identifiers: set[str],
    ) -> None:
        key = (ecosystem, name)
        package_entry = package_map.setdefault(
            key, {"ecosystem": ecosystem, "name": name, "versions": {}},
        )
        version_bucket = package_entry["versions"].setdefault(version, cls._init_version_bucket())
        if identifiers & version_bucket["ids"]:
            return
        version_bucket["ids"].update(identifiers)
        cls._add_vuln_to_bucket(version_bucket, vuln_details)

    @classmethod
    def _merge_version_bucket(cls, target: dict, source: dict) -> None:
        for vuln_details in source.get("cve_details", []) + source.get("malware_details", []):
            identifiers = cls._extract_vuln_identifiers(vuln_details.raw_details)
            if identifiers & target["ids"]:
                continue
            target["ids"].update(identifiers)
            cls._add_vuln_to_bucket(target, vuln_details)

    @classmethod
    def _merge_package_maps(
        cls,
        target: dict[tuple[str, str], dict],
        source: dict[tuple[str, str], dict],
    ) -> None:
        for key, source_entry in source.items():
            target_entry = target.setdefault(
                key, {"ecosystem": source_entry["ecosystem"], "name": source_entry["name"], "versions": {}},
            )
            for version, source_bucket in source_entry["versions"].items():
                target_bucket = target_entry["versions"].setdefault(
                    version, cls._init_version_bucket()
                )
                cls._merge_version_bucket(target_bucket, source_bucket)

    @classmethod
    def _build_purl_vulns_from_map(
        cls, package_map: dict[tuple[str, str], dict]
    ) -> list[PURLVulnsModel]:
        purl_vulns: list[PURLVulnsModel] = []
        for entry in package_map.values():
            groups: dict[str, dict] = {}
            alias_to_key: dict[str, str] = {}
            for version, bucket in entry["versions"].items():
                for vuln_details in bucket.get("cve_details", []) + bucket.get("malware_details", []):
                    identifiers = cls._extract_vuln_identifiers(vuln_details.raw_details)
                    key = None
                    for identifier in identifiers:
                        key = alias_to_key.get(identifier)
                        if key:
                            break
                    if not key:
                        key = vuln_details.id

                    group = groups.setdefault(key, {
                        "versions": set(),
                        "contains_cve": False,
                        "contains_malware": False,
                        "cve_details": [],
                        "malware_details": [],
                        "seen_ids": set(),
                    })

                    if version:
                        group["versions"].add(version)
                    for identifier in identifiers:
                        alias_to_key[identifier] = key

                    if identifiers & group["seen_ids"]:
                        group["seen_ids"].update(identifiers)
                        cls._merge_group_vuln_details(group, vuln_details)
                        continue
                    group["seen_ids"].update(identifiers)
                    cls._add_vuln_to_bucket(group, vuln_details)

            for group in groups.values():
                versions = sorted(v for v in group["versions"] if v)
                purl_vulns.append(
                    PURLVulnsModel(
                        ecosystem=entry["ecosystem"],
                        name=entry["name"],
                        versions=versions,
                        purl=cls._build_purl(
                            entry["ecosystem"], entry["name"],
                            versions[0] if versions else "",
                        ),
                        contains_cve=group["contains_cve"],
                        contains_malware=group["contains_malware"],
                        cve_details=group["cve_details"],
                        malware_details=group["malware_details"],
                    )
                )
        return purl_vulns

    @classmethod
    def _parse_depscan_purl(cls, bom_ref: str) -> Optional[tuple[str, str, str]]:

        if not bom_ref:
            return None
        purl_str = bom_ref
        if "pkg:" in bom_ref:
            purl_str = bom_ref[bom_ref.index("pkg:"):]
        try:
            purl = PackageURL.from_string(purl_str)
        except Exception:
            logger.warning(f"Invalid depscan bom-ref PURL: {purl_str}")
            return None
        if not purl.type:
            return None
        ecosystem = purl.type
        name = cls._normalize_package_name(purl.namespace, purl.name)
        version = purl.version or ""
        if not ecosystem or not name:
            return None
        return ecosystem, name, version

    @classmethod
    def _normalize_osv_package_info(cls, package_info: dict) -> Optional[tuple[str, str, str]]:
        ecosystem_value = package_info.get("ecosystem") or ""
        name_value = package_info.get("name") or ""
        version_value = package_info.get("version") or ""

        ecosystem = str(ecosystem_value).lower()
        name = str(name_value)
        version = str(version_value)
        if not ecosystem or not name:
            return None

        type_map = {
            "pypi": "pypi", "maven": "maven", "npm": "npm",
            "go": "golang", "rust": "cargo", "crates.io": "cargo",
            "nuget": "nuget", "rubygems": "gem", "packagist": "composer",
            "swifturl": "swift",
        }

        purl_type = type_map.get(ecosystem, ecosystem)
        namespace = None
        purl_name = name

        if purl_type == "npm" and name.startswith("@"):
            parts = name.split("/", 1)
            if len(parts) == 2:
                namespace = parts[0]
                purl_name = parts[1]
        elif purl_type == "maven":
            parts = name.split(":", 1)
            if len(parts) == 2:
                namespace = parts[0]
                purl_name = parts[1]
        elif purl_type in ["golang", "swift"]:
            parts = name.rsplit("/", 1)
            if len(parts) == 2:
                namespace = parts[0]
                purl_name = parts[1]

        normalized_name = cls._normalize_package_name(namespace, purl_name)
        if not normalized_name:
            return None
        return purl_type, normalized_name, version

    @staticmethod
    def _extract_vuln_identifiers(vuln: dict) -> set[str]:
        identifiers = set()
        vid = vuln.get("id")
        if vid:
            identifiers.add(vid)
        for alias in vuln.get("aliases", []) or []:
            if alias:
                identifiers.add(alias)
        for reference in vuln.get("references", []) or []:
            ref_id = reference.get("id") if isinstance(reference, dict) else None
            if ref_id:
                identifiers.add(ref_id)
        return identifiers

    @classmethod
    def _is_malware_vuln(cls, vuln_details: VulnDetails) -> bool:
        if vuln_details.id.startswith("MAL-"):
            return True
        for identifier in cls._extract_vuln_identifiers(vuln_details.raw_details):
            if identifier.startswith("MAL-"):
                return True
        return False


__all__ = ["SCAPipeline", "SCAScanResult", "PURLVulnsModel", "VulnDetails", "ScannerSourceEnum", "SCA_SUPPORTED_FILES"]

