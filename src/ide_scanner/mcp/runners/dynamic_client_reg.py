from typing import Any

from ..types import StatusEnum
from ..models import MetricRunOutput
from ..extractors.auth_modes import AuthModesResult

SCORE_DCR_AVAILABLE = 0.00
SCORE_DCR_UNAVAILABLE = 1.00
UNKNOWN_DEFAULT = 0.35


class DynamicClientRegRunner:
    """Scores Dynamic Client Registration support.

    Ported from RemoteAuthTestSuite.test_dynamic_client_registration().
    """

    version = "1.0"

    async def run(self, subject: Any, params: dict[str, Any]) -> MetricRunOutput:
        if subject is None:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Extractor was not run",
            )

        auth: AuthModesResult = subject

        # Skip for local servers
        if auth.is_local:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Not applicable for local servers",
            )

        if auth.oauth_metadata is None:
            return MetricRunOutput(
                score=UNKNOWN_DEFAULT,
                message="Could not determine DCR support",
                artifacts={"details": {"reason": "OAuth metadata unavailable"}},
            )

        has_dcr = bool(auth.oauth_metadata.registration_endpoint)
        if has_dcr:
            return MetricRunOutput(
                score=SCORE_DCR_AVAILABLE,
                message="Dynamic client registration endpoint is available",
                artifacts={
                    "details": {
                        "registration_endpoint": auth.oauth_metadata.registration_endpoint,
                        "dcr_available": True,
                    },
                },
            )
        else:
            return MetricRunOutput(
                score=SCORE_DCR_UNAVAILABLE,
                message="No dynamic client registration endpoint - manual registration required",
                artifacts={"details": {"registration_endpoint": None, "dcr_available": False}},
            )


__all__ = ["DynamicClientRegRunner"]

