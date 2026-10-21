"""SCAExtractor — runs SCA scanning and Datadog malicious manifest cross-referencing."""

import logging
from typing import Any, Optional

from pydantic import BaseModel, Field

from ..base import BaseExtractor
from .utils import strip_cache_noise
from ..sca_pipeline import SCAPipeline

logger = logging.getLogger(__name__)


class VulnDetail(BaseModel):
    """Single vulnerability detail from SCA scanning."""

    id: str
    transitive: bool = False
    reachable: bool = False
    exploitable: bool = False
    used_in_num_locations: int = 0
    severity: str = "UNKNOWN"
    scanner_source: Optional[str] = None
    raw_details: dict = Field(default_factory=dict)


class PURLVulns(BaseModel):
    """Vulnerability results for a single package."""

    ecosystem: str
    name: str
    versions: list[str] = Field(default_factory=list)
    purl: str = ""
    contains_cve: bool = False
    contains_malware: bool = False
    cve_details: list[VulnDetail] = Field(default_factory=list)
    malware_details: list[VulnDetail] = Field(default_factory=list)


class SCAResult(BaseModel):
    """Aggregated SCA scan results for dependency risk assessment."""

    success: bool = False
    has_repo: bool = False
    error_message: Optional[str] = None
    purl_vulns: list[PURLVulns] = Field(default_factory=list)
    dependencies: list[dict] = Field(default_factory=list)


class SCAExtractor(BaseExtractor):
    """Runs SCA scanning on the repository."""

    name = "sca_results"
    version = "1.0"
    cache_key_fn = staticmethod(strip_cache_noise)

    def __init__(self, cache_service, *, datadog_malicious_home=None):
        super().__init__(cache_service)
        self._datadog_malicious_home = datadog_malicious_home

    async def _compute(self, subject: Any, **kwargs) -> SCAResult:
        repo_path = subject.get("repo_path") if isinstance(subject, dict) else None
        if not repo_path:
            return SCAResult(has_repo=False)

        # Run SCA pipeline
        scan_result = await SCAPipeline.scan(repo_path)

        pipeline_vulns = scan_result.purl_vulns
        if self._datadog_malicious_home:
            manifests = SCAPipeline.load_datadog_manifests(self._datadog_malicious_home)
            pipeline_vulns = SCAPipeline.merge_datadog_malicious(
                pipeline_vulns, scan_result.dependencies, manifests
            )

        # Convert scanner models to v2 models
        purl_vulns = [
            PURLVulns(
                ecosystem=pv.ecosystem,
                name=pv.name,
                versions=pv.versions,
                purl=pv.purl or "",
                contains_cve=pv.contains_cve,
                contains_malware=pv.contains_malware,
                cve_details=[
                    VulnDetail(
                        id=vd.id,
                        transitive=vd.transitive,
                        reachable=vd.reachable,
                        exploitable=vd.exploitable,
                        used_in_num_locations=vd.used_in_num_locations,
                        severity=vd.severity or "UNKNOWN",
                        scanner_source=getattr(vd.scanner_source, "value", vd.scanner_source),
                        raw_details=vd.raw_details,
                    )
                    for vd in pv.cve_details
                ],
                malware_details=[
                    VulnDetail(
                        id=vd.id,
                        transitive=vd.transitive,
                        reachable=vd.reachable,
                        exploitable=vd.exploitable,
                        used_in_num_locations=vd.used_in_num_locations,
                        severity=vd.severity or "UNKNOWN",
                        scanner_source=getattr(vd.scanner_source, "value", vd.scanner_source),
                        raw_details=vd.raw_details,
                    )
                    for vd in pv.malware_details
                ],
            )
            for pv in pipeline_vulns
        ]

        return SCAResult(
            success=scan_result.success,
            has_repo=True,
            error_message=scan_result.error_message,
            purl_vulns=purl_vulns,
            dependencies=scan_result.dependencies,
        )


__all__ = [
    "SCAExtractor",
    "SCAResult",
    "PURLVulns",
    "VulnDetail",
]
