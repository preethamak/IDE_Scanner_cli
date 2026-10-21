"""McpCVERunner — scores CVE exposure for the MCP package itself."""

from typing import Any

from ..types import StatusEnum, VetoLevelEnum
from ..models import MetricRunOutput
from ..extractors.utils.osv import MCPVulnResult, MCPVulnSeverityEnum

SCORE_NO_CVES = 0.00
SCORE_NON_HIGH = 0.40
SCORE_NON_HIGH_LATEST = 0.70
SCORE_HIGH = 0.80
SCORE_HIGH_LATEST = 1.00


class McpCVERunner:
    """Scores known CVEs reported against the MCP server's package.

    Scores all reported advisories, but applies a higher penalty when OSV also
    reports that the current latest published package version is affected.
    """

    version = "1.0"

    async def run(self, subject: Any, params: dict[str, Any]) -> MetricRunOutput:
        if subject is None:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Extractor was not run",
            )

        result: MCPVulnResult = subject

        if not result.success:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.ERROR,
                message=result.error_message or "OSV query failed",
            )

        if not result.queryable:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="No OSV-queryable package identifier (unknown ecosystem)",
            )

        total = len(result.vulns)
        high_count = sum(
            1 for v in result.vulns if v.severity == MCPVulnSeverityEnum.HIGH
        )
        latest_count = sum(1 for v in result.vulns if v.affects_latest_version)
        latest_high_count = sum(
            1
            for v in result.vulns
            if v.affects_latest_version and v.severity == MCPVulnSeverityEnum.HIGH
        )
        veto = VetoLevelEnum.WARNING if latest_count > 0 else None
        veto_message = (
            "Known CVE(s) affect the latest published package version"
            if latest_count > 0
            else None
        )

        if total == 0:
            score = SCORE_NO_CVES
            message = "No known CVEs found"
        elif latest_high_count > 0:
            score = SCORE_HIGH_LATEST
            message = (
                f"{latest_high_count} HIGH severity CVE(s) affect the latest published version out of {total} total"
            )
        elif latest_count > 0:
            score = SCORE_NON_HIGH_LATEST
            if high_count > 0:
                message = (
                    f"{latest_count} CVE(s) affect the latest published version; "
                    f"{high_count} additional HIGH severity CVE(s) are historical "
                    f"({total} total)"
                )
            else:
                message = (
                    f"{latest_count} CVE(s) affect the latest published version out of {total} total"
                )
        elif high_count > 0:
            score = SCORE_HIGH
            message = f"{high_count} HIGH severity CVE(s) reported out of {total} total CVE(s)"
        else:
            score = SCORE_NON_HIGH
            message = f"Historical non-HIGH CVE(s) reported ({total} total)"

        return MetricRunOutput(
            score=score,
            veto=veto,
            veto_message=veto_message,
            message=message,
            artifacts={
                "details": {
                    "ecosystem": result.ecosystem,
                    "package_name": result.package_name,
                    "latest_version": result.latest_version,
                    "vulns": [v.model_dump(mode="json") for v in result.vulns],
                },
            },
        )


__all__ = ["McpCVERunner"]

