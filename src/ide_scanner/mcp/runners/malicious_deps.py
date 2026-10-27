from typing import Any

from ..types import StatusEnum, VetoLevelEnum
from ..models import MetricRunOutput
from ..extractors.sca import SCAResult

SCORE_NONE = 0.00
SCORE_FOUND = 1.00


class MaliciousDepsRunner:
    """Scores malicious dependency risk from SCA results.

    Ported from SourceCodeTestSuite.test_malicious_deps().
    """

    version = "1.0"

    async def run(self, subject: Any, params: dict[str, Any]) -> MetricRunOutput:
        if subject is None:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Extractor was not run",
            )

        sca: SCAResult = subject

        if not sca.has_repo:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Not applicable - no repository to scan",
            )

        if not sca.success:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.ERROR,
                message=f"Unable to scan dependencies: {sca.error_message or 'unknown error'}",
            )

        malicious_packages = [pv for pv in sca.purl_vulns if pv.contains_malware]
        malicious_count = len({(pv.ecosystem, pv.name) for pv in malicious_packages})

        if malicious_count > 0:
            return MetricRunOutput(
                score=SCORE_FOUND,
                veto=VetoLevelEnum.FAILURE,
                veto_message="Malicious dependencies detected",
                message=f"Malicious dependencies detected in {malicious_count} package(s)",
                artifacts={
                    "details": {
                        "malicious_count": malicious_count,
                        "results": [pv.model_dump(mode="json") for pv in malicious_packages],
                    },
                },
            )
        else:
            return MetricRunOutput(
                score=SCORE_NONE,
                message="No malicious dependencies found",
                artifacts={"details": {"malicious_count": 0}},
            )


__all__ = ["MaliciousDepsRunner"]

