from typing import Any

from ..types import StatusEnum
from ..models import MetricRunOutput
from ..extractors.auth_modes import AuthModesResult

SCORE_S256_ONLY = 0.00
SCORE_S256_WITH_PLAIN = 0.60
SCORE_NO_S256 = 1.00
UNKNOWN_DEFAULT = 0.35


class PKCEValidationRunner:
    """Scores PKCE configuration from OAuth metadata.

    Ported from RemoteAuthTestSuite.test_pkce_validation().
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

        # No OAuth metadata available
        if auth.oauth_metadata is None:
            return MetricRunOutput(
                score=UNKNOWN_DEFAULT,
                message="Could not determine PKCE configuration",
                artifacts={"details": {"reason": "OAuth metadata unavailable"}},
            )

        methods = auth.oauth_metadata.code_challenge_methods_supported or []
        s256_supported = "S256" in methods
        plain_supported = "plain" in methods

        if not s256_supported:
            score = SCORE_NO_S256
            message = "Mandatory PKCE method 'S256' is not supported"
        elif plain_supported:
            score = SCORE_S256_WITH_PLAIN
            message = "Insecure PKCE method 'plain' is supported alongside 'S256'"
        else:
            score = SCORE_S256_ONLY
            message = "PKCE configuration is secure - 'S256' method is supported"

        return MetricRunOutput(
            score=score,
            message=message,
            artifacts={
                "details": {
                    "code_challenge_methods_supported": methods,
                    "s256_supported": s256_supported,
                    "plain_supported": plain_supported,
                },
            },
        )


__all__ = ["PKCEValidationRunner"]

