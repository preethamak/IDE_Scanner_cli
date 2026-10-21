from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

from .models import MetricResult, MetricRunOutput, MetricSpec, higher_veto
from .types import StatusEnum


def _value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): _value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_value(item) for item in value]
    if hasattr(value, "value"):
        return value.value
    return value


class MetricExecutionEngine:
    """Async metric execution and weighted aggregation matching the reference engine."""

    def __init__(self, **runners: Any) -> None:
        self.runners = runners

    async def async_execute(self, *, spec: MetricSpec, subject: Any) -> MetricResult:
        if spec.is_module:
            children = list(await asyncio.gather(*(
                self.async_execute(spec=child, subject=subject) for child in spec.children
            )))
            usable = [child for child in children if child.score is not None]
            denominator = sum(child.weight for child in usable)
            score = sum(float(child.score or 0.0) * child.weight for child in usable) / denominator if denominator else None
            veto = higher_veto(*(child.veto for child in children))
            veto_message = next((child.veto_message for child in children if child.veto == veto and child.veto_message), None)
            return MetricResult(
                name=spec.name,
                title=spec.title,
                weight=spec.weight,
                score=score,
                status="success" if score is not None else "skipped",
                message=f"{len(usable)} of {len(children)} metrics assessed" if usable else "No evidence available for this module",
                veto=veto,
                veto_message=veto_message,
                children=children,
            )

        runner = self.runners[spec.runner or ""]
        runner_key = spec.runner or ""
        try:
            runner_subject = _subject_for_runner(subject, runner_key)
            output: MetricRunOutput = await runner.run(subject=runner_subject, params={})
        except Exception as exc:
            output = MetricRunOutput(score=None, status=StatusEnum.ERROR, message=str(exc), details={"error": str(exc)})
        status = output.status.value if hasattr(output.status, "value") else output.status
        veto = output.veto.value if hasattr(output.veto, "value") else output.veto
        details = _value(output.details)
        details.setdefault("runner", runner_key)
        details.setdefault("runner_version", getattr(runner, "version", "1.0"))
        details["execution_id"] = hashlib.sha256(json.dumps({"runner": runner_key, "subject": _value(runner_subject)}, sort_keys=True, default=str).encode()).hexdigest()
        return MetricResult(
            name=spec.name,
            title=spec.title,
            weight=spec.weight,
            score=output.score,
            status=status,
            message=output.message or "",
            veto=veto,
            veto_message=output.veto_message,
            details=details,
        )


def _subject_for_runner(subject: dict[str, Any], runner_key: str) -> Any:
    return {
        "hosting_operator_class": subject.get("classification"),
        "transport_security": subject.get("fingerprint"),
        "auth_strength": subject.get("auth_modes"),
        "pkce_validation": subject.get("auth_modes"),
        "dynamic_client_registration": subject.get("auth_modes"),
        "source_opacity": subject.get("classification"),
        "malicious_dependencies": subject.get("sca_results"),
        "vulnerability_risk": subject.get("sca_results"),
        "mcp_package_cves": subject.get("mcp_vulns"),
        "metadata_security": subject.get("tool_analysis"),
        "tool_source_code_security": subject.get("tool_source_code_analysis"),
        "secrets_risk": subject.get("secrets_scan"),
    }.get(runner_key)

