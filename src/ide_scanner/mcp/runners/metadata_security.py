from typing import Any

from ..types import StatusEnum, VetoLevelEnum
from ..models import MetricRunOutput
from ..extractors.tool_analysis import ToolAnalysisResult

SCORE_NO_FINDINGS = 0.00
SCORE_HAS_FINDINGS = 1.00


class MetadataSecurityRunner:
    """Scores tool metadata security (tool poisoning patterns).

    Ported from ToolCapabilityTestSuite.test_metadata_security().
    """

    version = "1.0"

    async def run(self, subject: Any, params: dict[str, Any]) -> MetricRunOutput:
        if subject is None:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Extractor was not run",
            )

        tool_analysis: ToolAnalysisResult = subject

        if not tool_analysis.tools:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.ERROR,
                message="Could not analyze tool metadata. No tools were provided.",
            )

        has_tier1 = len(tool_analysis.tier1_findings) > 0

        if has_tier1:
            categories = list({f.category for f in tool_analysis.tier1_findings})
            return MetricRunOutput(
                score=SCORE_HAS_FINDINGS,
                veto=VetoLevelEnum.FAILURE,
                veto_message="Tool poisoning patterns detected in tool's metadata",
                message=f"{len(tool_analysis.tier1_findings)} tool poisoning pattern(s) detected: {', '.join(categories)}",
                artifacts={
                    "details": {
                        "has_tier1_findings": True,
                        "tier1_findings": [f.model_dump() for f in tool_analysis.tier1_findings],
                        "tier1_finding_count": len(tool_analysis.tier1_findings),
                        "tier2_findings": [f.model_dump() for f in tool_analysis.tier2_findings],
                        "tier2_finding_count": len(tool_analysis.tier2_findings),
                        "tool_tags": [t.model_dump() for t in tool_analysis.tool_tags],
                    },
                },
            )
        else:
            return MetricRunOutput(
                score=SCORE_NO_FINDINGS,
                message="No tool poisoning patterns detected",
                artifacts={
                    "details": {
                        "has_tier1_findings": False,
                        "tier1_findings": [],
                        "tier1_finding_count": 0,
                        "tier2_findings": [f.model_dump() for f in tool_analysis.tier2_findings],
                        "tier2_finding_count": len(tool_analysis.tier2_findings),
                        "tool_tags": [t.model_dump() for t in tool_analysis.tool_tags],
                    },
                },
            )


__all__ = ["MetadataSecurityRunner"]

