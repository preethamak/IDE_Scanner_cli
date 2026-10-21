from enum import Enum
from typing import Any

from ..types import OfficialityEnum
from ..types import StatusEnum
from ..types import VetoLevelEnum
from ..models import MetricRunOutput
from ..extractors.classification import ClassificationResult


class HostingClassEnum(str, Enum):
    REMOTE_OFFICIAL = "remote_official"
    LOCAL_OFFICIAL = "local_official"
    LOCAL_COMMUNITY = "local_community"
    REMOTE_COMMUNITY = "remote_community"


SCORE_REMOTE_OFFICIAL = 0.00
SCORE_LOCAL_OFFICIAL = 0.15
SCORE_LOCAL_COMMUNITY = 0.50
SCORE_REMOTE_COMMUNITY = 1.00


class HostingOperatorClassRunner:
    """Scores hosting/operator classification based on locality and officiality.

    Ported from TrustDataFlowTestSuite.test_hosting_class().
    """

    version = "1.0"

    async def run(self, subject: Any, params: dict[str, Any]) -> MetricRunOutput:
        if subject is None:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Extractor was not run",
            )

        classification: ClassificationResult = subject
        is_local = classification.is_local
        is_official = classification.officiality == OfficialityEnum.OFFICIAL

        if not is_local and is_official:
            hosting_class = HostingClassEnum.REMOTE_OFFICIAL
            score = SCORE_REMOTE_OFFICIAL
        elif is_local and is_official:
            hosting_class = HostingClassEnum.LOCAL_OFFICIAL
            score = SCORE_LOCAL_OFFICIAL
        elif is_local and not is_official:
            hosting_class = HostingClassEnum.LOCAL_COMMUNITY
            score = SCORE_LOCAL_COMMUNITY
        else:
            hosting_class = HostingClassEnum.REMOTE_COMMUNITY
            score = SCORE_REMOTE_COMMUNITY

        veto = None
        veto_message = None
        message = classification.message
        if hosting_class == HostingClassEnum.REMOTE_COMMUNITY:
            veto = VetoLevelEnum.WARNING
            veto_message = "Remote community MCP may proxy credentials/data through third-party infrastructure"

        return MetricRunOutput(
            score=score,
            veto=veto,
            veto_message=veto_message,
            message=message,
            artifacts={"details": {"hosting_class": hosting_class.value}},
        )


__all__ = ["HostingOperatorClassRunner"]
