from typing import Any

from ..types import StatusEnum, VetoLevelEnum
from ..models import MetricRunOutput
from ..extractors.secrets import SecretsScanResult

SCORE_NO_SECRETS = 0.00
SCORE_SECRETS_FOUND = 1.00


class SecretsRiskRunner:
    """Scores secrets detection risk.

    Ported from SecretsTestSuite.test_secrets_detection().
    """

    version = "1.0"

    async def run(self, subject: Any, params: dict[str, Any]) -> MetricRunOutput:
        if subject is None:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Extractor was not run",
            )

        secrets: SecretsScanResult = subject

        if not secrets.has_repo:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Not applicable - no repository to scan",
            )

        if secrets.error:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.ERROR,
                message=f"Secrets detection failed: {secrets.error}",
            )

        if secrets.secrets_count > 0:
            friendly_names = sorted({finding.rule_id for finding in secrets.secrets_found})
            message = f"Secrets found - {', '.join(friendly_names)}" if friendly_names else "Secrets found"
            return MetricRunOutput(
                score=SCORE_SECRETS_FOUND,
                veto=VetoLevelEnum.FAILURE,
                veto_message="Hardcoded secrets found in source code",
                message=message,
                artifacts={
                    "details": {
                        "secrets_found": [
                            finding.model_dump(by_alias=True, exclude_none=True)
                            for finding in secrets.secrets_found
                        ],
                    },
                },
            )
        else:
            return MetricRunOutput(
                score=SCORE_NO_SECRETS,
                message="No secrets found",
                artifacts={"details": {"secrets_found": []}},
            )


__all__ = ["SecretsRiskRunner"]

