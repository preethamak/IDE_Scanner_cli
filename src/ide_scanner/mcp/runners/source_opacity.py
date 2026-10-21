from enum import Enum
from typing import Any

from ..types import OfficialityEnum
from ..types import StatusEnum
from ..models import MetricRunOutput
from ..extractors.classification import ClassificationResult


class OpacityLevelEnum(str, Enum):
    OPEN_SOURCE = "open_source"
    REMOTE_OFFICIAL_CLOSED = "remote_official_closed"
    LOCAL_OFFICIAL_CLOSED = "local_official_closed"
    REMOTE_COMMUNITY_CLOSED = "remote_community_closed"
    LOCAL_COMMUNITY_CLOSED = "local_community_closed"


SCORE_OPEN_SOURCE = 0.00
SCORE_REMOTE_OFFICIAL_CLOSED = 0.00
SCORE_LOCAL_OFFICIAL_CLOSED = 0.40
SCORE_REMOTE_COMMUNITY_CLOSED = 0.70
SCORE_LOCAL_COMMUNITY_CLOSED = 1.00


class SourceOpacityRunner:
    """Scores source code opacity based on classification.

    Ported from SourceCodeTestSuite.test_opacity().
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
        has_repo = classification.has_repo

        if has_repo:
            opacity = OpacityLevelEnum.OPEN_SOURCE
            score = SCORE_OPEN_SOURCE
        elif not is_local and is_official:
            opacity = OpacityLevelEnum.REMOTE_OFFICIAL_CLOSED
            score = SCORE_REMOTE_OFFICIAL_CLOSED
        elif is_local and is_official:
            opacity = OpacityLevelEnum.LOCAL_OFFICIAL_CLOSED
            score = SCORE_LOCAL_OFFICIAL_CLOSED
        elif not is_local and not is_official:
            opacity = OpacityLevelEnum.REMOTE_COMMUNITY_CLOSED
            score = SCORE_REMOTE_COMMUNITY_CLOSED
        else:
            opacity = OpacityLevelEnum.LOCAL_COMMUNITY_CLOSED
            score = SCORE_LOCAL_COMMUNITY_CLOSED

        messages = {
            OpacityLevelEnum.OPEN_SOURCE: "Open source code",
            OpacityLevelEnum.REMOTE_OFFICIAL_CLOSED: "Remote official MCP with closed source code",
            OpacityLevelEnum.LOCAL_OFFICIAL_CLOSED: "Local official MCP with closed source code",
            OpacityLevelEnum.REMOTE_COMMUNITY_CLOSED: "Remote community MCP with closed source code",
            OpacityLevelEnum.LOCAL_COMMUNITY_CLOSED: "Local community MCP with closed source code",
        }

        return MetricRunOutput(
            score=score,
            message=messages[opacity],
            artifacts={
                "details": {
                    "opacity_level": opacity.value,
                    "has_repo": has_repo,
                    "is_local": is_local,
                    "is_official": is_official,
                },
            },
        )


__all__ = ["SourceOpacityRunner"]

