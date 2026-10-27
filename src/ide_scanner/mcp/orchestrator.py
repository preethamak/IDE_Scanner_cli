from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .engine import MetricExecutionEngine
from .extractors import (
    AuthModesExtractor,
    ClassificationExtractor,
    FingerprintExtractor,
    McpCVEExtractor,
    SCAExtractor,
    SecretsExtractor,
    ToolAnalysisExtractor,
)
from .runners import (
    AuthStrengthRunner,
    DynamicClientRegRunner,
    HostingOperatorClassRunner,
    MaliciousDepsRunner,
    McpCVERunner,
    MetadataSecurityRunner,
    PKCEValidationRunner,
    SecretsRiskRunner,
    SourceOpacityRunner,
    ToolSourceCodeSecurityRunner,
    TransportSecurityRunner,
    VulnerabilityRiskRunner,
)
from .spec import MCP_CATALOG_RISK_SPEC

logger = logging.getLogger(__name__)


@dataclass
class ServerCatalogRiskConfig:
    gh_token: str | None = None
    gh_tokens: list[str] | None = None
    vertex_project_id: str | None = None
    google_api_key: str | None = None
    google_search_cx: str | None = None
    env: str | None = None
    datadog_malicious_home: str | None = None


@asynccontextmanager
async def _repository_context(server_input: dict[str, Any]):
    repo_path = server_input.get("repo_path")
    if repo_path:
        yield server_input
        return
    repo_url = str(server_input.get("repo_url") or "").strip()
    if not repo_url:
        yield server_input
        return
    temp_dir = Path(tempfile.mkdtemp(prefix="guardrails-mcp-repo-"))
    try:
        process = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--filter=blob:none", "--no-tags", repo_url, str(temp_dir / "repo"),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            _stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError("repository clone timed out")
        if process.returncode != 0:
            raise RuntimeError(stderr.decode("utf-8", errors="replace")[-1000:])
        yield {**server_input, "repo_path": str(temp_dir / "repo")}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


class ServerCatalogRiskOrchestrator:
    def __init__(self, cache_service: Any = None, config: ServerCatalogRiskConfig | None = None) -> None:
        self._cache_service = cache_service
        self._config = config or ServerCatalogRiskConfig()

    async def evaluate(self, server_input: dict[str, Any]) -> dict[str, Any]:
        async with _repository_context(server_input) as enriched_input:
            return await self._run(enriched_input)

    async def _run(self, server_input: dict[str, Any]) -> dict[str, Any]:
        cfg = self._config
        common = {
            "cache_service": self._cache_service,
            "gh_token": cfg.gh_token,
            "gh_tokens": cfg.gh_tokens,
            "vertex_project_id": cfg.vertex_project_id,
            "google_api_key": cfg.google_api_key,
            "google_search_cx": cfg.google_search_cx,
            "env": cfg.env,
        }
        classification_ext = ClassificationExtractor(**common)
        fingerprint_ext = FingerprintExtractor(self._cache_service)
        auth_modes_ext = AuthModesExtractor(
            common["cache_service"],
            vertex_project_id=cfg.vertex_project_id,
            google_api_key=cfg.google_api_key,
            google_search_cx=cfg.google_search_cx,
            env=cfg.env,
        )
        sca_ext = SCAExtractor(self._cache_service, datadog_malicious_home=cfg.datadog_malicious_home)
        mcp_cve_ext = McpCVEExtractor(self._cache_service)
        tool_analysis_ext = ToolAnalysisExtractor(**{key: common[key] for key in ("cache_service", "gh_token", "gh_tokens", "vertex_project_id", "env")})
        secrets_ext = SecretsExtractor(**{key: common[key] for key in ("cache_service", "vertex_project_id", "env")})

        classification_result, fingerprint, auth_modes, sca, mcp_vulns, tool_analysis, secrets = await asyncio.gather(
            classification_ext.extract(server_input),
            fingerprint_ext.extract(server_input),
            auth_modes_ext.extract(server_input),
            sca_ext.extract(server_input),
            mcp_cve_ext.extract(server_input),
            tool_analysis_ext.extract(server_input),
            secrets_ext.extract(server_input),
        )
        if isinstance(classification_result, tuple):
            classification, classification_artifact = classification_result
        else:
            classification, classification_artifact = classification_result, None

        subject = {
            "classification": classification,
            "fingerprint": fingerprint,
            "auth_modes": auth_modes,
            "sca_results": sca,
            "mcp_vulns": mcp_vulns,
            "tool_analysis": tool_analysis,
            "tool_source_code_analysis": tool_analysis.tool_source_code_analysis if tool_analysis else None,
            "secrets_scan": secrets,
        }
        engine = MetricExecutionEngine(
            **{
                "hosting_operator_class": HostingOperatorClassRunner(),
                "transport_security": TransportSecurityRunner(),
                "auth_strength": AuthStrengthRunner(),
                "pkce_validation": PKCEValidationRunner(),
                "dynamic_client_registration": DynamicClientRegRunner(),
                "source_opacity": SourceOpacityRunner(),
                "malicious_dependencies": MaliciousDepsRunner(),
                "vulnerability_risk": VulnerabilityRiskRunner(),
                "mcp_package_cves": McpCVERunner(),
                "metadata_security": MetadataSecurityRunner(),
                "tool_source_code_security": ToolSourceCodeSecurityRunner(),
                "secrets_risk": SecretsRiskRunner(),
            }
        )
        metrics = await engine.async_execute(spec=MCP_CATALOG_RISK_SPEC, subject=subject)
        leaves = _leaves(metrics)
        veto = next((item.veto for item in sorted(leaves, key=lambda item: {"failure": 2, "warning": 1, None: 0}.get(item.veto, 0), reverse=True) if item.veto), None)
        risk_score = None if metrics.score is None else round(metrics.score * 100, 1)
        decision = "block" if veto == "failure" else "review" if veto == "warning" or (metrics.score is not None and metrics.score >= 0.60) else "allow" if metrics.score is not None else "incomplete"
        assessed = [item for item in leaves if item.score is not None and item.status == "success"]
        return {
            "schema_version": "guardrails.mcp-risk-report.v1",
            "scanner": {"name": "GuardRails MCP scanner", "mode": "full", "version": "2.0"},
            "subject": _public_subject(server_input, subject),
            "decision": decision,
            "risk_score": risk_score,
            "veto": veto,
            "coverage": {"percent": round((len(assessed) / len(leaves)) * 100, 1) if leaves else 0.0, "assessed_metrics": len(assessed), "total_metrics": len(leaves), "unavailable_metrics": len(leaves) - len(assessed), "unavailable": [item.name for item in leaves if item not in assessed]},
            "metrics": metrics.as_dict(),
            "classification": _json_value(classification),
            "classification_artifact": _json_value(classification_artifact),
            "auth_modes": _json_value(auth_modes),
            "tools": _json_value(tool_analysis.tools if tool_analysis else []),
        }


def _leaves(result: Any) -> list[Any]:
    out: list[Any] = []
    for child in result.children:
        out.extend(_leaves(child) if child.children else [child])
    return out


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if hasattr(value, "value"):
        return value.value
    return value


def _public_subject(server_input: dict[str, Any], subject: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": server_input.get("name") or server_input.get("title") or "Unnamed MCP server",
        "url": server_input.get("mcp_url") or server_input.get("url"),
        "repo_url": server_input.get("repo_url"),
        "is_local": bool(server_input.get("is_local")) or not bool(server_input.get("mcp_url") or server_input.get("url")),
        "tool_count": len(getattr(subject.get("tool_analysis"), "tools", []) or server_input.get("tools", []) or []),
    }


__all__ = ["ServerCatalogRiskConfig", "ServerCatalogRiskOrchestrator"]
