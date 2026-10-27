"""AuthModesExtractor — detects authentication modes and probes OAuth metadata."""

import json
import logging
import random
import re
from typing import Any, Optional, Union
from urllib.parse import urlparse

import httpx
import tiktoken
from google.genai.types import ThinkingConfig, ThinkingLevel
from httpx import HTTPError, InvalidURL
from langfuse import get_client
from pydantic import BaseModel, Field

from ..types import AuthModeEnum, AuthSummaryEnum
from ..web_research import google_search, scrape_page
from ..base import BaseExtractor, DoNotCache
from ..llm import GeminiVertexLLM
from .utils import strip_cache_noise

logger = logging.getLogger(__name__)


class OAuthMetadataResult(BaseModel):
    """Subset of OAuth discovery metadata relevant to auth assessment."""

    code_challenge_methods_supported: Optional[list[str]] = None
    registration_endpoint: Optional[str] = None


class AuthModesResult(BaseModel):
    """Authentication modes and OAuth metadata for the MCP server."""

    modes: Optional[list[AuthModeEnum]] = None
    summary: str = ""
    is_local: bool = False
    oauth_metadata: Optional[OAuthMetadataResult] = None


class AuthModesDetailLLMResponseFormat(BaseModel):
    """LLM response model for auth classification."""
    modes: Optional[list[AuthModeEnum]] = Field(
        description="Authentication modes supported by the MCP server"
    )
    summary: str = Field(description="Two concise sentences summarising the evidence.")


class AuthModesExtractor(BaseExtractor):
    """Detects authentication modes and probes OAuth metadata."""

    name = "auth_modes"
    version = "1.1"
    cache_key_fn = staticmethod(strip_cache_noise)
    TIMEOUT = 10
    MCP_PROTOCOL_VERSION = "2025-11-25"
    TOOL_PROBE_SAMPLE_SIZE = 3
    API_KEY_PATTERNS = (
        re.compile(r"\bgenerate an api[ -]?key\b", re.IGNORECASE),
        re.compile(r"\brequires authentication via api[ -]?key\b", re.IGNORECASE),
        re.compile(r"\binclude(?: your)? api[ -]?key\b", re.IGNORECASE),
        re.compile(r"\bapi[ -]?key.{0,40}authorization header\b", re.IGNORECASE),
        re.compile(r"\bauthorization header.{0,40}api[ -]?key\b", re.IGNORECASE),
        re.compile(r"\bapi[ -]?key.{0,40}bearer token\b", re.IGNORECASE),
        re.compile(r"\bbearer token.{0,40}api[ -]?key\b", re.IGNORECASE),
    )
    API_KEY_CONTEXT_TERMS = (
        re.compile(r"\bapi[ -]?key\b", re.IGNORECASE),
        re.compile(r"\bx-api-key\b", re.IGNORECASE),
    )
    AUTH_REQUIRED_PATTERNS = (
        re.compile(r"\bauthentication (?:is )?required\b", re.IGNORECASE),
        re.compile(r"\bmissing bearer token\b", re.IGNORECASE),
        re.compile(r"\bauthenticate yourself\b", re.IGNORECASE),
        re.compile(r"\byou need to authenticate\b", re.IGNORECASE),
        re.compile(r"\brequires authentication\b", re.IGNORECASE),
        re.compile(r"\brequires an api key\b", re.IGNORECASE),
        re.compile(r"\bpass it as a bearer token\b", re.IGNORECASE),
        re.compile(r"\bincluding your api key\b", re.IGNORECASE),
        re.compile(r"\bonly allowed with personal access tokens\b", re.IGNORECASE),
    )
    AUTH_CONTEXT_TERMS = (
        re.compile(r"\bapi key\b", re.IGNORECASE),
        re.compile(r"\bbearer token\b", re.IGNORECASE),
        re.compile(r"\baccess token\b", re.IGNORECASE),
        re.compile(r"\bpersonal access tokens?\b", re.IGNORECASE),
        re.compile(r"\boauth\b", re.IGNORECASE),
    )
    NON_AUTH_FAILURE_PATTERNS = (
        re.compile(r"\binvalid\b", re.IGNORECASE),
        re.compile(r"\bnot a valid\b", re.IGNORECASE),
        re.compile(r"\bmalformed\b", re.IGNORECASE),
        re.compile(r"\bhttp 400\b", re.IGNORECASE),
        re.compile(r"\b(?:either|one of).+\bis required\b", re.IGNORECASE),
    )

    def __init__(
        self,
        cache_service,
        *,
        vertex_project_id=None,
        google_api_key=None,
        google_search_cx=None,
        env=None,
    ):
        super().__init__(cache_service)
        self._vertex_project_id = vertex_project_id
        self._google_api_key = google_api_key
        self._google_search_cx = google_search_cx
        self._env = env

    async def _compute(self, subject: Any, **kwargs) -> Union[AuthModesResult, DoNotCache[AuthModesResult]]:
        mcp_url = subject.get("mcp_url") if isinstance(subject, dict) else None
        repo_url = subject.get("repo_url") if isinstance(subject, dict) else None
        is_local = subject.get("is_local", False) if isinstance(subject, dict) else False
        discovery = subject.get("discovery") if isinstance(subject, dict) else None

        if is_local or not mcp_url:
            return AuthModesResult(is_local=True)

        # Probe remote auth modes
        probe_modes = await self._probe_remote_auth_modes(mcp_url, discovery)
        final_modes = list(probe_modes or [])

        # If no NO_AUTH, try LLM classification
        search_result = None
        llm_failed = False
        if AuthModeEnum.NO_AUTH not in final_modes:
            search_result = await self._classify_auth_modes_with_search(mcp_url, repo_url)
            if search_result is None:
                llm_failed = True
            elif search_result.modes:
                for mode in search_result.modes:
                    if mode not in final_modes:
                        final_modes.append(mode)

        # Don't cache if probe failed, or if LLM was called but failed
        if probe_modes is None or llm_failed:
            return DoNotCache(AuthModesResult(modes=final_modes or None, summary="", is_local=False),
                              reason="HTTP probe failed" if probe_modes is None else "LLM classification failed")

        # Remove UNKNOWN if other modes present
        real_modes = [m for m in final_modes if m != AuthModeEnum.UNKNOWN]
        if real_modes:
            final_modes = real_modes

        # Compute summary
        if AuthModeEnum.NO_AUTH in final_modes and len(final_modes) == 1:
            summary = AuthSummaryEnum.NO_AUTH.value
        else:
            summary = self._get_auth_summary(final_modes)

        # Probe OAuth metadata
        oauth_metadata = await self._probe_oauth_metadata(mcp_url, discovery)

        return AuthModesResult(
            modes=final_modes if final_modes else None,
            summary=summary,
            is_local=False,
            oauth_metadata=oauth_metadata,
        )

    async def _probe_remote_auth_modes(
        self,
        mcp_url: str,
        discovery: Optional[Any],
    ) -> Optional[list[AuthModeEnum]]:
        """Probe authentication modes via HTTP headers and well-known endpoints."""
        parsed = urlparse(mcp_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        host = (parsed.hostname or "").lower()

        if host.endswith("smithery.ai"):
            return [AuthModeEnum.OAUTH]

        modes = []

        if discovery and hasattr(discovery, "authorization_endpoint") and discovery.authorization_endpoint:
            modes.append(AuthModeEnum.OAUTH)

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT, follow_redirects=True) as client:
                # Check well-known OAuth endpoints
                if AuthModeEnum.OAUTH not in modes:
                    path_wk = base_url + "/.well-known/oauth-protected-resource" + parsed.path
                    root_wk = base_url + "/.well-known/oauth-protected-resource"
                    for wk_url in (path_wk, root_wk):
                        if AuthModeEnum.OAUTH in modes:
                            break
                        try:
                            prm_resp = await client.get(wk_url)
                            if prm_resp.status_code == 200:
                                prm_data = prm_resp.json()
                                if prm_data.get("authorization_servers"):
                                    modes.append(AuthModeEnum.OAUTH)
                        except Exception:
                            pass

                # Check response headers
                try:
                    resp = await client.get(mcp_url)
                    www_auth = resp.headers.get("www-authenticate", "").lower().strip()
                    body = (resp.text[:1000] if resp.text else "").lower()

                    if "resource_metadata" in www_auth and AuthModeEnum.OAUTH not in modes:
                        modes.append(AuthModeEnum.OAUTH)

                    if resp.status_code in (401, 402, 403) and AuthModeEnum.API_KEY not in modes:
                        if re.search(
                            r"(provide|missing|no).{0,25}api.?key|api.?key.{0,15}required",
                            body,
                        ):
                            modes.append(AuthModeEnum.API_KEY)

                    if AuthModeEnum.API_KEY not in modes:
                        if any(pattern.search(body) for pattern in self.API_KEY_PATTERNS):
                            modes.append(AuthModeEnum.API_KEY)
                        elif (
                            re.search(r"\b(401|402|403|unauthorized|required|missing)\b", body)
                            and any(pattern.search(body) for pattern in self.API_KEY_CONTEXT_TERMS)
                        ):
                            modes.append(AuthModeEnum.API_KEY)

                    if AuthModeEnum.API_KEY not in modes and www_auth == "key":
                        modes.append(AuthModeEnum.API_KEY)

                    if AuthModeEnum.OAUTH not in modes and AuthModeEnum.API_KEY not in modes:
                        if await self._confirm_no_auth(mcp_url):
                            modes.append(AuthModeEnum.NO_AUTH)
                except httpx.RequestError:
                    if not modes:
                        return None

        except (HTTPError, InvalidURL):
            return None

        return modes if modes else [AuthModeEnum.UNKNOWN]

    async def _confirm_no_auth(self, mcp_url: str) -> bool:
        """Verify if MCP server requires no authentication by probing initialize, tools/list, and tools/call."""
        init_payload = json.dumps({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": self.MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "friendly-auth-probe", "version": "1.0.0"},
            },
        }).encode("utf-8")

        headers = {
            "Accept": "text/event-stream, application/json",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT, follow_redirects=True) as client:
                init_resp = await client.post(mcp_url, headers=headers, content=init_payload)
                if init_resp.status_code != 200:
                    return False

                session_id = self._extract_session_id(init_resp)

                tools_headers = headers.copy()
                if session_id:
                    tools_headers["Mcp-Session-Id"] = session_id

                tools_payload = self._build_tools_list_payload()
                tools_resp = await client.post(mcp_url, headers=tools_headers, content=tools_payload)
                if tools_resp.status_code != 200:
                    return False

                tools_response_payload = self._parse_response_payload(tools_resp)
                tools = self._extract_tools(tools_response_payload)
                probe_tools = self._sample_probe_tools(tools, sample_size=self.TOOL_PROBE_SAMPLE_SIZE)
                if not probe_tools:
                    return False

                saw_non_auth_evidence = False
                request_id = 3
                for probe_tool in probe_tools:
                    arguments = self._build_probe_arguments(probe_tool)
                    tool_call_payload = self._build_tool_call_payload(
                        tool_name=probe_tool["name"],
                        arguments=arguments,
                        request_id=request_id,
                    )
                    request_id += 1
                    tool_call_resp = await client.post(
                        mcp_url, headers=tools_headers, content=tool_call_payload
                    )
                    status_code, response_text = self._normalize_tool_call_response(tool_call_resp)

                    if self._tool_call_indicates_auth(response_text):
                        return False
                    if status_code in [200, 422]:
                        saw_non_auth_evidence = True
                        continue

                return saw_non_auth_evidence
        except Exception:
            return False

    @staticmethod
    def _build_tools_list_payload() -> bytes:
        return json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 2,
            "params": {},
        }).encode("utf-8")

    @staticmethod
    def _build_tool_call_payload(tool_name: str, arguments: dict[str, Any], request_id: int) -> bytes:
        return json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": request_id,
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }).encode("utf-8")

    @staticmethod
    def _extract_session_id(response: httpx.Response) -> Optional[str]:
        return response.headers.get("mcp-session-id") or response.headers.get("Mcp-Session-Id")

    @staticmethod
    def _parse_response_payload(response: httpx.Response) -> Optional[dict[str, Any]]:
        """Parse a JSON-RPC payload from either a plain JSON response or SSE-wrapped `data:` frames."""
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass

        for block in response.text.split("\n\n"):
            data_lines = []
            for line in block.splitlines():
                if line.startswith("data:"):
                    data_lines.append(line[len("data:"):].strip())
            if not data_lines:
                continue
            try:
                payload = json.loads("\n".join(data_lines))
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and payload.get("jsonrpc") == "2.0":
                return payload
        return None

    @staticmethod
    def _extract_tools(payload: Optional[dict[str, Any]]) -> list[dict[str, Any]]:
        """Extract the `result.tools` list from a parsed MCP JSON-RPC response."""
        if not isinstance(payload, dict):
            return []
        result = payload.get("result", {})
        if not isinstance(result, dict):
            return []
        tools = result.get("tools", [])
        return tools if isinstance(tools, list) else []

    @staticmethod
    def _sample_probe_tools(tools: list[dict[str, Any]], *, sample_size: int) -> list[dict[str, Any]]:
        """Sample a small set of named tools to probe so auth checks do not depend on a single tool."""
        candidates = [
            tool for tool in tools
            if isinstance(tool, dict) and isinstance(tool.get("name"), str) and tool["name"]
        ]
        if not candidates:
            return []
        return random.sample(candidates, k=min(sample_size, len(candidates)))

    def _example_value_from_schema(
        self, schema: Optional[dict[str, Any]], *, field_name: str = "value"
    ) -> Any:
        """Build a minimal synthetic value from a JSON Schema fragment for MCP tool-call probing."""
        schema = schema or {}
        schema_type = schema.get("type")
        description = str(schema.get("description") or "").lower()
        lowered_field = field_name.lower()

        if "default" in schema:
            return schema["default"]
        if schema.get("enum"):
            return schema["enum"][0]
        if schema_type == "string":
            if schema.get("format") == "uri":
                return "https://example.com"
            min_length = schema.get("minLength", 1)
            if "prompt" in lowered_field or "prompt" in description:
                value = "Test prompt for MCP tool probing and validation."
            elif "query" in lowered_field:
                value = "sample-query"
            elif "context" in lowered_field:
                value = "sample-context"
            elif "tag" in lowered_field or "id" in lowered_field:
                value = f"test-{lowered_field}"
            else:
                value = f"sample-{lowered_field}"
            if len(value) < min_length:
                value = value + ("x" * (min_length - len(value)))
            return value
        if schema_type == "integer":
            minimum = schema.get("minimum", 0)
            return int(minimum if minimum > 0 else 1)
        if schema_type == "number":
            minimum = schema.get("minimum", 0)
            return float(minimum if minimum > 0 else 1)
        if schema_type == "boolean":
            return False
        if schema_type == "array":
            items = schema.get("items", {})
            return [self._example_value_from_schema(items, field_name=field_name)]
        if schema_type == "object" or "properties" in schema:
            properties = schema.get("properties", {}) or {}
            required = set(schema.get("required", []) or [])
            return {
                key: self._example_value_from_schema(value, field_name=key)
                for key, value in properties.items()
                if key in required or (isinstance(value, dict) and "default" in value)
            }
        return "sample-value"

    def _build_probe_arguments(self, tool: dict[str, Any]) -> dict[str, Any]:
        """Construct minimal arguments for required tool inputs, preserving nested defaults when present."""
        schema = tool.get("inputSchema") or {}
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        required = schema.get("required", []) if isinstance(schema, dict) else []
        if not isinstance(properties, dict) or not isinstance(required, list):
            return {}
        return {
            field_name: self._example_value_from_schema(
                properties.get(field_name), field_name=field_name
            )
            for field_name in required
        }

    def _normalize_tool_call_response(
        self, response: httpx.Response
    ) -> tuple[int, str]:
        """Normalize a tool-call response into `(status_code, response_text)`."""
        payload = self._parse_response_payload(response)
        return (
            response.status_code,
            self._collect_response_text(payload, response.text),
        )

    @staticmethod
    def _collect_response_text(payload: Optional[dict[str, Any]], raw_text: str) -> str:
        """Flatten raw, textual, and structured MCP result content into one searchable string."""
        parts = [raw_text]
        if isinstance(payload, dict):
            result = payload.get("result", {})
            if isinstance(result, dict):
                content = result.get("content", [])
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and isinstance(item.get("text"), str):
                            parts.append(item["text"])
                structured = result.get("structuredContent")
                if structured is not None:
                    try:
                        parts.append(json.dumps(structured))
                    except TypeError:
                        parts.append(str(structured))
        return "\n".join(part for part in parts if part)

    def _tool_call_indicates_auth(self, response_text: str) -> bool:
        """Detect auth-required tool-call responses, including MCP servers that wrap auth failures in HTTP 200."""
        lowered = response_text.lower()

        if any(pattern.search(response_text) for pattern in self.AUTH_REQUIRED_PATTERNS):
            return True
        if "forbidden" in lowered and any(pattern.search(response_text) for pattern in self.AUTH_CONTEXT_TERMS):
            return True
        if ("unauthorized" in lowered or re.search(r"\b(401|403)\b", lowered)) and any(
            pattern.search(response_text) for pattern in self.AUTH_CONTEXT_TERMS
        ):
            return True
        return False

    async def _classify_auth_modes_with_search(
        self, mcp_url: str, repo_url: Optional[str]
    ) -> Optional[AuthModesDetailLLMResponseFormat]:
        """Use Google Search + LLM to classify auth modes from documentation."""
        if not self._google_api_key or not self._google_search_cx:
            return None

        search_query = f"Authentication methods for {mcp_url} MCP server {repo_url or ''}"
        try:
            docs_urls = await google_search(
                query=search_query,
                k=8,
                or_terms=[
                    "documentation", "readme", "docs", "guide",
                    "auth", "oauth", "api key", "personal access token", "pat",
                ],
                google_api_key=self._google_api_key,
                google_search_cx=self._google_search_cx,
            )
        except Exception as e:
            logger.warning(f"Search failed for {search_query} - {e}")
            docs_urls = []

        if not docs_urls:
            return None

        content_parts = [
            f"{'-' * 10}URL: {doc_url}\n{page_content}\n{'-' * 10}"
            for doc_url in docs_urls
            if (page_content := await scrape_page(doc_url))
        ]
        search_results = "\n".join(content_parts) if content_parts else ""
        if search_results:
            search_results = self._truncate_text(search_results, 200_000)

        langfuse_client = get_client()
        prompt = langfuse_client.get_prompt("mcp-repo-auth-modes", label=self._env)
        gemini = GeminiVertexLLM(
            model="google/gemini-3-flash-preview",
            project_id=self._vertex_project_id,
        )

        try:
            result: AuthModesDetailLLMResponseFormat = await gemini.agenerate(
                messages=prompt.compile(
                    mcp_url=mcp_url,
                    repo_url=repo_url or "N/A",
                    search_results=search_results,
                ),
                response_format=AuthModesDetailLLMResponseFormat,
                max_tokens=-1,
                thinking_config=ThinkingConfig(thinking_level=ThinkingLevel.LOW),
            )
        except Exception as e:
            logger.warning(f"LLM failed to classify auth modes for {mcp_url} - {e}")
            return None

        if not result.modes:
            return AuthModesDetailLLMResponseFormat(modes=[AuthModeEnum.UNKNOWN], summary=result.summary)

        # Remove NO_AUTH from LLM modes (we have higher-confidence checks)
        modes = [mode for mode in result.modes if mode != AuthModeEnum.NO_AUTH]

        return AuthModesDetailLLMResponseFormat(modes=modes, summary=result.summary)

    async def _probe_oauth_metadata(
        self, mcp_url: str, discovery: Optional[Any]
    ) -> Optional[OAuthMetadataResult]:
        """Probe OAuth authorization server metadata."""
        if discovery and hasattr(discovery, "code_challenge_methods_supported"):
            reg = getattr(discovery, "registration_endpoint", None)
            return OAuthMetadataResult(
                code_challenge_methods_supported=getattr(
                    discovery, "code_challenge_methods_supported", None
                ),
                registration_endpoint=str(reg) if reg is not None else None,
            )

        # Try .well-known discovery
        parsed = urlparse(mcp_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for wk_path in (
            f"/.well-known/oauth-authorization-server{parsed.path}",
            "/.well-known/oauth-authorization-server",
        ):
            try:
                async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                    resp = await client.get(base_url + wk_path)
                    if resp.status_code == 200:
                        data = resp.json()
                        return OAuthMetadataResult(
                            code_challenge_methods_supported=data.get(
                                "code_challenge_methods_supported"
                            ),
                            registration_endpoint=data.get("registration_endpoint"),
                        )
            except Exception:
                continue
        return None

    @staticmethod
    def _get_auth_summary(modes: list[AuthModeEnum]) -> str:
        has_oauth = AuthModeEnum.OAUTH in modes
        has_api_key = AuthModeEnum.API_KEY in modes
        has_pat = AuthModeEnum.PAT in modes

        if has_oauth and has_api_key and has_pat:
            return AuthSummaryEnum.OAUTH_API_KEY_PAT.value
        if has_oauth and has_api_key:
            return AuthSummaryEnum.OAUTH_API_KEY.value
        if has_oauth and has_pat:
            return AuthSummaryEnum.OAUTH_PAT.value
        if has_oauth:
            return AuthSummaryEnum.OAUTH.value
        if has_api_key and has_pat:
            return AuthSummaryEnum.API_KEY_PAT.value
        if has_api_key:
            return AuthSummaryEnum.API_KEY.value
        if has_pat:
            return AuthSummaryEnum.PAT.value
        return AuthSummaryEnum.UNKNOWN.value

    @staticmethod
    def _truncate_text(text: str, target_token_count: int) -> str:
        encoding = tiktoken.get_encoding("cl100k_base")
        token_count = len(encoding.encode(text, disallowed_special=()))
        while token_count > target_token_count:
            truncate_ratio = target_token_count / token_count
            approximate_char_length = int(len(text) * truncate_ratio)
            text = text[:approximate_char_length]
            token_count = len(encoding.encode(text, disallowed_special=()))
        return text


__all__ = [
    "AuthModesExtractor",
    "AuthModesResult",
    "OAuthMetadataResult",
]

