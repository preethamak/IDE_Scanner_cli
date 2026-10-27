"""McpCVEExtractor — looks up known CVEs for the MCP package itself via OSV."""

import logging
from typing import Any

from ..base import BaseExtractor
from .utils import strip_cache_noise
from .utils.osv import MCPVulnResult, OSVQueryPipeline

logger = logging.getLogger(__name__)


class McpCVEExtractor(BaseExtractor):
    """
    Queries OSV for advisories filed against the MCP server's package (currently version agnostic).
    """

    name = "mcp_vulns"
    version = "1.0"
    cache_key_fn = staticmethod(strip_cache_noise)

    async def _compute(self, subject: Any, **kwargs) -> MCPVulnResult:
        pkg_cmd = subject.get("package")
        repo_url = subject.get("repo_url")
        return await OSVQueryPipeline.query(pkg_cmd, repo_url)


__all__ = [
    "McpCVEExtractor",
    "MCPVulnResult"
]

