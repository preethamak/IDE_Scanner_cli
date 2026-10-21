from typing import Any

from ..types import StatusEnum, VetoLevelEnum
from ..models import MetricRunOutput
from ..extractors.tool_analysis import ToolSourceCodeAnalysisResult

SCORE_NO_FINDINGS = 0.00
SCORE_T2_ONLY = 0.60
SCORE_HAS_FINDINGS = 0.75
SCORE_HAS_HIGH_SEV = 1.00


class ToolSourceCodeSecurityRunner:
    """Scores tool source code security from taint flow analysis.

    Ported from ToolCapabilityTestSuite.test_tool_source_code_security().
    """

    version = "1.0"

    async def run(self, subject: Any, params: dict[str, Any]) -> MetricRunOutput:
        if subject is None:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Extractor was not run",
            )

        tool_source_code_analysis: ToolSourceCodeAnalysisResult = subject

        if not tool_source_code_analysis.has_repo:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.SKIPPED,
                message="Not applicable - no repository to scan",
            )

        if not tool_source_code_analysis.tools:
            return MetricRunOutput(
                score=None,
                status=StatusEnum.ERROR,
                message="Could not analyze source code for tools' vulnerabilities. No tools were provided.",
            )

        tier1_count = tool_source_code_analysis.source_code_tier1_count
        tier2_count = tool_source_code_analysis.source_code_tier2_count

        has_t1_high = any(
            f.severity == "high" and f.tier == 1
            for f in tool_source_code_analysis.source_code_findings
        )

        if tier1_count == 0 and tier2_count == 0:
            score = SCORE_NO_FINDINGS
            message = "No security issues detected in tools' source code"
        else:
            parts = []
            if tier1_count > 0:
                parts.append(f"{tier1_count} high risk finding(s) detected in tool source code")
            if tier2_count > 0:
                parts.append(f"{tier2_count} medium risk finding(s) detected in tool source code")
            message = ", ".join(parts)

            if tier1_count == 0:
                score = SCORE_T2_ONLY
            elif has_t1_high:
                score = SCORE_HAS_HIGH_SEV
            else:
                score = SCORE_HAS_FINDINGS

        veto = VetoLevelEnum.FAILURE if has_t1_high else None
        veto_message = "High risk finding(s) detected in tool source code" if has_t1_high else None

        return MetricRunOutput(
            score=score,
            veto=veto,
            veto_message=veto_message,
            message=message,
            artifacts={
                "details": {
                    "tier1_count": tier1_count,
                    "tier2_count": tier2_count,
                    "findings": [f.model_dump() for f in tool_source_code_analysis.source_code_findings],
                    "tool_tags": [t.model_dump() for t in tool_source_code_analysis.tool_tags],
                },
            },
        )


__all__ = ["ToolSourceCodeSecurityRunner"]

