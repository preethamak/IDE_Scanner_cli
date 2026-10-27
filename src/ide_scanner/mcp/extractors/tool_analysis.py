"""ToolAnalysisExtractor — tool metadata security + source code taint flow analysis."""

import json
import logging
from enum import Enum
from pathlib import Path
from typing import Any, Optional, cast, Union

import tiktoken
from gitingest import ingest_async
from google.genai.types import ThinkingConfig, ThinkingLevel
from langfuse import get_client
from mcp import Tool as ToolModel
from pydantic import BaseModel, Field

from ..base import BaseExtractor, DoNotCache
from ..llm import GeminiVertexLLM
from .utils import strip_cache_noise
from .utils.github import GitHubClient

logger = logging.getLogger(__name__)


def _coerce_tool_model(value: dict[str, Any]) -> ToolModel:
    data = dict(value)
    data.setdefault("inputSchema", {"type": "object", "properties": {}})
    return ToolModel(**data)


# --- Metadata security enums ---

class ToolPoisoningCategory(str, Enum):
    """Tier 1: Security vulnerabilities in tool metadata (Tool Poisoning patterns)."""

    HIDDEN_DIRECTIVE = "hidden_directive"
    INVISIBLE_CHARS = "invisible_chars"
    CROSS_TOOL_REFERENCE = "cross_tool_reference"
    SENSITIVE_PATH_REFERENCE = "sensitive_path_reference"
    ENCODED_INSTRUCTIONS = "encoded_instructions"
    SEMANTIC_MISMATCH = "semantic_mismatch"
    EXFILTRATION_INSTRUCTION = "exfiltration_instruction"
    FORCED_USAGE_WITH_EXFIL_CAPABILITY = "forced_usage_with_exfil_capability"


class HighRiskCapabilityCategory(str, Enum):
    """Tier 2: High-risk capabilities declared in tool metadata (informational)."""

    CODE_EXECUTION = "code_execution"
    FILE_SYSTEM_ACCESS = "file_system_access"
    DATABASE_ACCESS = "database_access"
    NETWORK_ACCESS = "network_access"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    CREDENTIAL_HANDLING = "credential_handling"
    PROCESS_CONTROL = "process_control"
    BROWSER_AUTOMATION = "browser_automation"


class MetadataCWEIdentifier(str, Enum):
    """CWE identifiers for metadata-level findings."""

    CWE_22 = "CWE-22"
    CWE_89 = "CWE-89"
    CWE_94 = "CWE-94"
    CWE_116 = "CWE-116"
    CWE_200 = "CWE-200"
    CWE_441 = "CWE-441"
    CWE_451 = "CWE-451"
    CWE_522 = "CWE-522"
    CWE_918 = "CWE-918"


# --- Source code tag enums ---

class ToolSourceCodeCapabilityTagEnum(str, Enum):
    CAP_EXEC_SHELL = "cap_exec_shell"
    CAP_EXEC_PROCESS = "cap_exec_process"
    CAP_EXEC_SCRIPT = "cap_exec_script"
    CAP_EXEC_EVAL = "cap_exec_eval"
    CAP_EXEC_BUILD = "cap_exec_build"
    CAP_FS_READ = "cap_fs_read"
    CAP_FS_WRITE = "cap_fs_write"
    CAP_FS_DELETE = "cap_fs_delete"
    CAP_NET_FETCH = "cap_net_fetch"
    CAP_NET_EGRESS = "cap_net_egress"
    CAP_NET_LOCALHOST = "cap_net_localhost"
    CAP_NET_INTERNAL = "cap_net_internal"
    CAP_SECRETS_READ = "cap_secrets_read"
    CAP_DB_QUERY = "cap_db_query"
    CAP_DB_MODIFY = "cap_db_modify"


class ToolSourceCodeInterfaceInTagEnum(str, Enum):
    IFACE_IN_COMMAND = "iface_in_command"
    IFACE_IN_PATH = "iface_in_path"
    IFACE_IN_URL = "iface_in_url"
    IFACE_IN_CODE = "iface_in_code"
    IFACE_IN_CREDENTIAL = "iface_in_credential"
    IFACE_IN_ID = "iface_in_id"
    IFACE_IN_TEXT = "iface_in_text"
    IFACE_IN_JSON = "iface_in_json"


class ToolSourceCodeInterfaceOutTagEnum(str, Enum):
    IFACE_OUT_TEXT = "iface_out_text"
    IFACE_OUT_JSON = "iface_out_json"
    IFACE_OUT_PATH = "iface_out_path"
    IFACE_OUT_URL = "iface_out_url"
    IFACE_OUT_COMMAND = "iface_out_command"
    IFACE_OUT_CODE = "iface_out_code"
    IFACE_OUT_ERROR = "iface_out_error"


# --- Source code vulnerability enums ---

class SourceCodeSecurityFindingId(str, Enum):
    T1_01 = "t1_01"
    T1_02 = "t1_02"
    T1_03 = "t1_03"
    T1_04 = "t1_04"
    T1_05 = "t1_05"
    T1_06 = "t1_06"
    T1_07 = "t1_07"
    T1_08 = "t1_08"
    T1_09 = "t1_09"
    T1_10 = "t1_10"
    T1_11 = "t1_11"
    T1_12 = "t1_12"
    T2_01 = "t2_01"
    T2_02 = "t2_02"
    T2_03 = "t2_03"
    T2_04 = "t2_04"
    T2_05 = "t2_05"
    T2_06 = "t2_06"
    T2_07 = "t2_07"
    T2_08 = "t2_08"


class SourceCodeSecuritySeverityLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NA = "na"


class SourceCodeSecurityConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"


class SourceCodeSecurityCweId(str, Enum):
    CWE_22 = "cwe_22"
    CWE_94 = "cwe_94"
    CWE_89 = "cwe_89"
    CWE_295 = "cwe_295"
    CWE_327 = "cwe_327"
    CWE_346 = "cwe_346"
    CWE_352 = "cwe_352"
    CWE_502 = "cwe_502"
    CWE_522 = "cwe_522"
    CWE_526 = "cwe_526"
    CWE_532 = "cwe_532"
    CWE_611 = "cwe_611"
    CWE_613 = "cwe_613"
    CWE_639 = "cwe_639"
    CWE_668 = "cwe_668"
    CWE_918 = "cwe_918"
    CWE_1336 = "cwe_1336"
    LLM_01 = "llm_01"
    LLM_02 = "llm_02"


class ToolSrcCodeVulnName(str, Enum):
    CODE_EXECUTION = "code_execution"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    CREDENTIAL_EXFILTRATION = "credential_exfiltration"
    TOOL_POISONING = "tool_poisoning"
    IDOR = "idor"
    INSECURE_NETWORK_BINDING = "insecure_network_binding"
    MISSING_ORIGIN_VALIDATION = "missing_origin_validation"
    ENV_VARIABLE_EXPOSURE = "env_variable_exposure"
    XXE = "xxe"
    SSTI = "ssti"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    OAUTH_STATE_MISSING = "oauth_state_missing"
    UNSANITIZED_LLM_CONTENT = "unsanitized_llm_content"
    MISSING_TLS_VALIDATION = "missing_tls_validation"
    INSECURE_TOKEN_STORAGE = "insecure_token_storage"
    SECRET_IN_LOG_OUTPUT = "secret_in_log_output"
    MISSING_TOKEN_ROTATION = "missing_token_rotation"


_F = SourceCodeSecurityFindingId
_S = SourceCodeSecuritySeverityLevel
_C = SourceCodeSecurityCweId

# fmt: off
_SEVERITY_MAP: dict[
    SourceCodeSecurityFindingId,
    tuple[SourceCodeSecuritySeverityLevel, SourceCodeSecuritySeverityLevel],
] = {
    _F.T1_01: (_S.HIGH, _S.HIGH),
    _F.T1_02: (_S.HIGH, _S.HIGH),
    _F.T1_03: (_S.HIGH, _S.HIGH),
    _F.T1_04: (_S.HIGH, _S.HIGH),
    _F.T1_05: (_S.HIGH, _S.HIGH),
    _F.T1_06: (_S.HIGH, _S.HIGH),
    _F.T1_07: (_S.HIGH, _S.HIGH),
    _F.T1_08: (_S.MEDIUM, _S.HIGH),
    _F.T1_09: (_S.HIGH, _S.NA),
    _F.T1_10: (_S.HIGH, _S.HIGH),
    _F.T1_11: (_S.HIGH, _S.HIGH),
    _F.T2_01: (_S.MEDIUM, _S.HIGH),
    _F.T2_02: (_S.HIGH, _S.HIGH),
    _F.T2_03: (_S.MEDIUM, _S.HIGH),
    _F.T2_04: (_S.LOW, _S.HIGH),
    _F.T2_05: (_S.HIGH, _S.HIGH),
    _F.T2_06: (_S.NA, _S.HIGH),
    _F.T2_07: (_S.HIGH, _S.HIGH),
    _F.T1_12: (_S.HIGH, _S.HIGH),
    _F.T2_08: (_S.MEDIUM, _S.HIGH),
}

_CWE_MAP: dict[SourceCodeSecurityFindingId, SourceCodeSecurityCweId] = {
    _F.T1_01: _C.CWE_94,
    _F.T1_02: _C.CWE_89,
    _F.T1_03: _C.CWE_22,
    _F.T1_04: _C.CWE_918,
    _F.T1_05: _C.CWE_502,
    _F.T1_06: _C.CWE_522,
    _F.T1_07: _C.LLM_01,
    _F.T1_08: _C.CWE_639,
    _F.T1_09: _C.CWE_668,
    _F.T1_10: _C.CWE_346,
    _F.T1_11: _C.CWE_526,
    _F.T2_01: _C.CWE_611,
    _F.T2_02: _C.CWE_1336,
    _F.T2_03: _C.CWE_327,
    _F.T2_04: _C.CWE_352,
    _F.T2_05: _C.LLM_02,
    _F.T2_06: _C.CWE_295,
    _F.T2_07: _C.CWE_522,
    _F.T1_12: _C.CWE_532,
    _F.T2_08: _C.CWE_613,
}


# fmt: on


def _get_source_code_security_severity(
        finding_id: SourceCodeSecurityFindingId, is_remote: bool,
) -> SourceCodeSecuritySeverityLevel:
    severities = _SEVERITY_MAP.get(finding_id)
    if severities is None:
        return SourceCodeSecuritySeverityLevel.NA
    if finding_id.value.startswith("t2"):
        severity = severities[1] if is_remote else severities[0]
        if severity == SourceCodeSecuritySeverityLevel.NA:
            return severity
        return SourceCodeSecuritySeverityLevel.MEDIUM
    return severities[1] if is_remote else severities[0]


def _get_source_code_security_cwe(
        finding_id: SourceCodeSecurityFindingId,
) -> Optional[SourceCodeSecurityCweId]:
    return _CWE_MAP.get(finding_id)


# --- Metadata security finding models ---

class ToolPoisoningFinding(BaseModel):
    """A specific tool poisoning vulnerability detected in metadata."""

    finding_id: str = Field(..., description="Unique identifier like T1-POISON-01-001")
    tool_name: str = Field(..., description="Name of the tool where finding was detected")
    category: ToolPoisoningCategory
    confidence: str = Field(default="HIGH")
    location: str = Field(
        ..., description="Location in metadata (e.g., 'description', 'parameter:url')"
    )
    evidence: str = Field(..., description="Exact text snippet that triggered detection")
    cwe: Optional[MetadataCWEIdentifier] = Field(default=None)
    explanation: str = Field(..., description="Why this is considered malicious")


class HighRiskCapabilityFinding(BaseModel):
    """A high-risk capability aggregated across tools (informational, not a vulnerability)."""

    finding_id: str = Field(..., description="Unique identifier like T2-CAP-001")
    category: HighRiskCapabilityCategory
    confidence: str = Field(default="HIGH")
    explanation: str = Field(..., description="Brief description of the capability")
    tools_with_capability: list[str] = Field(
        ..., description="List of tool names with this capability"
    )
    cwe: Optional[MetadataCWEIdentifier] = Field(default=None)


# --- LLM response models ---

class MetadataSecurityLLMResponseFormat(BaseModel):
    """LLM output for metadata poisoning + capability detection."""

    tier1_findings: list[ToolPoisoningFinding] = Field(default_factory=list)
    tier2_findings: list[HighRiskCapabilityFinding] = Field(default_factory=list)
    tool_tags: list[dict] = Field(default_factory=list)  # not used for scoring


class TaintSourceLocationLLMResponseFormat(BaseModel):
    file: str
    parameter: str
    code: str


class TaintPropagationStepLLMResponseFormat(BaseModel):
    step: int
    file: str
    code: str


class TaintSinkLocationLLMResponseFormat(BaseModel):
    file: str
    function: str
    code: str


class SanitizerInfoLLMResponseFormat(BaseModel):
    present: bool
    adequate: bool
    details: Optional[str] = None


class TaintFlowLLMResponseFormat(BaseModel):
    source: TaintSourceLocationLLMResponseFormat
    propagation: Optional[list[TaintPropagationStepLLMResponseFormat]] = None
    sink: TaintSinkLocationLLMResponseFormat
    sanitizer: SanitizerInfoLLMResponseFormat


class ToolSrcCodeVulnFindingLLMResponseFormat(BaseModel):
    finding_id: str
    finding_type_id: SourceCodeSecurityFindingId
    finding_type_name: ToolSrcCodeVulnName
    confidence: SourceCodeSecurityConfidenceLevel
    affected_tools: list[str]
    taint_flow: TaintFlowLLMResponseFormat
    explanation: str
    remediation: str


class VulnerabilityAnalysisLLMResponseFormat(BaseModel):
    findings: list[ToolSrcCodeVulnFindingLLMResponseFormat]


class JSONSchemaObject(BaseModel):
    """Minimal JSON Schema object for tool parameters."""

    type: str = Field(default="object", description='Must be "object" for tool parameters')
    properties: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Map of parameter name -> JSON Schema for that parameter",
    )
    required: Optional[list[str]] = Field(
        default=None,
        description="List of required parameter names, if any",
    )


# --- Deep tool enrichment models ---

class OperationKindEnum(str, Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    WRITE = "write"


class DestructiveLevelEnum(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ExtraToolDetailsLLMResponseFormat(BaseModel):
    name: str
    operation_kind: OperationKindEnum
    destructive_level: DestructiveLevelEnum
    dangerous_params: list[str] = Field(default_factory=list)
    human_readable_description: str


class DeepToolAnalysisLLMResponseFormat(BaseModel):
    tools: list[ExtraToolDetailsLLMResponseFormat]


# --- Source code tool dump models ---


class ToolSrcCodeTagLLMResponseFormat(BaseModel):
    """Source-code-derived capability/interface tags (pure tag fields, no name)."""

    capability_tags: list[ToolSourceCodeCapabilityTagEnum] = Field(default_factory=list)
    input_tags: list[ToolSourceCodeInterfaceInTagEnum] = Field(default_factory=list)
    output_tags: list[ToolSourceCodeInterfaceOutTagEnum] = Field(default_factory=list)


class ToolSrcCodeNamedTagLLMResponseFormat(ToolSrcCodeTagLLMResponseFormat):
    """Tag fields with tool name — for matching tags to existing tool instances."""

    tool_name: str = Field(..., description="Name of the tool these tags apply to")


class SourceConstructedToolModel(ToolSrcCodeTagLLMResponseFormat):
    """Tool constructed from source code with source-derived tags, prior to deep enrichment."""

    name: str = Field(description="Stable tool identifier as exposed by the server")
    description: Optional[str] = Field(default=None)
    inputSchema: JSONSchemaObject = Field(
        description="JSON Schema object for the tool's input parameters",
    )

# TODO: uncomment this when okay
# class ToolAnnotationsObject(BaseModel):
#     """Tool annotation hints exposed to clients."""
#
#     title: Optional[str] = None
#     readOnlyHint: Optional[bool] = None
#     destructiveHint: Optional[bool] = None
#     idempotentHint: Optional[bool] = None
#     openWorldHint: Optional[bool] = None


# class IconObject(BaseModel):
#     """Icon metadata for a tool."""
#
#     src: str
#     mimeType: Optional[str] = None
#     sizes: Optional[list[str]] = None

class DeepToolModel(ExtraToolDetailsLLMResponseFormat, ToolSrcCodeTagLLMResponseFormat):
    """Unified tool model — LLM response format and stored result."""

    # title: Optional[str] = Field(
    #     default=None,
    #     description="Human facing title for the tool",
    # )
    name: str = Field(description="Stable tool identifier as exposed by the server")
    description: Optional[str] = Field(default=None)
    inputSchema: JSONSchemaObject = Field(
        description="JSON Schema object for the tool's input parameters",
    )
    # outputSchema: Optional[JSONSchemaObject] = Field(
    #     default=None,
    #     description="JSON Schema object describing the tool's output, if known.",
    # )
    # annotations: Optional[ToolAnnotationsObject] = Field(
    #     default=None,
    #     description="Optional MCP tool annotation hints such as title and read-only/destructive behavior.",
    # )
    # icons: Optional[list[IconObject]] = Field(
    #     default=None,
    #     description="Optional icon metadata exposed by the tool.",
    # )


class SourceCodeToolDumpAndTagsLLMResponseFormat(BaseModel):
    """LLM builds tools from source with source-derived tags only."""

    tools: list[SourceConstructedToolModel] = Field(
        description="List of all tools with construction and source-derived tags filled in"
    )


class ToolSrcCodeTagsLLMResponseFormat(BaseModel):
    """Used for the live-tool tagging path — tags matched to existing tools by name."""

    tool_tags: list[ToolSrcCodeNamedTagLLMResponseFormat] = Field(
        description="Source code derived tags for each tool"
    )


# --- Result models (runner-facing) ---

class ToolSourceCodeFinding(BaseModel):
    """A source-code-level security finding from taint flow analysis."""

    finding_id: str
    finding_type_id: str
    finding_type_name: str
    tier: int
    severity: str
    confidence: str
    affected_tools: list[str] = Field(default_factory=list)
    cwe: Optional[str] = None
    explanation: str = ""
    remediation: str = ""
    taint_flow: Optional[dict] = None


class ToolTagInfo(BaseModel):
    """Source-code-derived tags for a tool, stored in the result."""

    tool_name: str
    capability_tags: list[str] = Field(default_factory=list)
    input_tags: list[str] = Field(default_factory=list)
    output_tags: list[str] = Field(default_factory=list)


class ToolSourceCodeAnalysisResult(BaseModel):
    """Tool source-code security analysis."""

    has_repo: bool = False
    tools: list[DeepToolModel] = Field(default_factory=list)
    tool_tags: list[ToolTagInfo] = Field(default_factory=list)

    source_code_findings: list[ToolSourceCodeFinding] = Field(default_factory=list)
    source_code_tier1_count: int = 0
    source_code_tier2_count: int = 0


class ToolAnalysisResult(BaseModel):
    """Tool metadata analysis plus nested source code security analysis."""

    has_repo: bool = False
    is_local: bool = False

    tools: list[DeepToolModel] = Field(default_factory=list)

    tier1_findings: list[ToolPoisoningFinding] = Field(default_factory=list)
    tier2_findings: list[HighRiskCapabilityFinding] = Field(default_factory=list)
    tool_tags: list[ToolTagInfo] = Field(default_factory=list)
    tool_source_code_analysis: Optional[ToolSourceCodeAnalysisResult] = None


class ToolSourceCodeAnalysisExtractor(BaseExtractor):
    """Runs tool source code taint flow analysis using precomputed tool/codebase input."""

    name = "tool_source_code_analysis"
    version = "1.0"

    def __init__(
            self,
            cache_service,
            *,
            vertex_project_id=None,
            env=None,
    ):
        super().__init__(cache_service)
        self._vertex_project_id = vertex_project_id
        self._env = env

    async def _compute(
            self, subject: Any, **kwargs,
    ) -> Union[ToolSourceCodeAnalysisResult, DoNotCache[ToolSourceCodeAnalysisResult]]:
        has_repo = subject.get("has_repo", False) if isinstance(subject, dict) else False
        is_local = subject.get("is_local", False) if isinstance(subject, dict) else False
        tools = subject.get("tools", []) if isinstance(subject, dict) else []
        tool_tags = subject.get("tool_tags", []) if isinstance(subject, dict) else []
        tree = subject.get("tree", "") if isinstance(subject, dict) else ""
        codebase = subject.get("codebase", "") if isinstance(subject, dict) else ""

        if not has_repo:
            return ToolSourceCodeAnalysisResult(
                has_repo=False,
                tools=tools,
                tool_tags=tool_tags,
            )

        if not tools:
            return ToolSourceCodeAnalysisResult(
                has_repo=True,
                tools=[],
                tool_tags=tool_tags,
            )

        try:
            source_code_findings = await self._analyze_source_code_security(
                tools,
                is_local,
                tree,
                codebase,
            )
        except Exception as e:
            return DoNotCache(
                ToolSourceCodeAnalysisResult(
                    has_repo=True,
                    tools=tools,
                    tool_tags=tool_tags,
                ),
                reason=f"LLM source code security analysis failed: {e}",
            )

        applicable = [f for f in source_code_findings if f.severity != "na"]
        source_code_tier1_count = sum(1 for f in applicable if f.tier == 1)
        source_code_tier2_count = sum(1 for f in applicable if f.tier == 2)

        return ToolSourceCodeAnalysisResult(
            has_repo=True,
            tools=tools,
            tool_tags=tool_tags,
            source_code_findings=source_code_findings,
            source_code_tier1_count=source_code_tier1_count,
            source_code_tier2_count=source_code_tier2_count,
        )

    async def _analyze_source_code_security(
            self,
            tools: list[DeepToolModel],
            is_local: bool,
            tree: str,
            codebase: str,
    ) -> list[ToolSourceCodeFinding]:
        """Run LLM-based taint-flow vulnerability analysis on source code."""
        is_remote = not is_local

        source_code = json.dumps({"tree": tree, "content": codebase})
        tools_dump = json.dumps([t.model_dump() for t in tools])

        deployment_mode = "REMOTE" if is_remote else "LOCAL"
        deployment_desc = (
            "This server is deployed REMOTELY (accessible via HTTP/SSE transport over the network)."
            if is_remote
            else "This server is deployed LOCALLY (runs on user's machine via STDIO or potentially HTTP/SSE transport as well; use the source code to know this)."
        )

        langfuse_client = get_client()
        vuln_prompt = langfuse_client.get_prompt("tool-vuln-src-code-analysis", label=self._env)
        verification_prompt = langfuse_client.get_prompt(
            "tool-vuln-verification-src-code-analysis", label=self._env
        )

        gemini = GeminiVertexLLM(
            model="google/gemini-3-flash-preview",
            project_id=self._vertex_project_id,
            provider="gemini-vertex",
        )

        vuln_messages = cast(
            list[dict[str, Any]],
            vuln_prompt.compile(
                deployment_mode=deployment_mode,
                deployment_desc=deployment_desc,
                tools_dump=tools_dump,
                source_code=source_code,
            ),
        )

        try:
            vuln_response: VulnerabilityAnalysisLLMResponseFormat = await gemini.agenerate(
                messages=vuln_messages,
                response_format=VulnerabilityAnalysisLLMResponseFormat,
                max_tokens=-1,
            )
        except Exception as e:
            logger.warning(f"Source code vulnerability analysis failed: {e}")
            raise

        first_pass_result = vuln_response.model_dump_json()
        verify_prompt_text: str = verification_prompt.compile()

        try:
            verified_response: VulnerabilityAnalysisLLMResponseFormat = await gemini.agenerate(
                messages=vuln_messages
                         + [
                             {"role": "model", "content": first_pass_result},
                             {"role": "user", "content": verify_prompt_text},
                         ],
                response_format=VulnerabilityAnalysisLLMResponseFormat,
                max_tokens=-1,
                thinking_config=ThinkingConfig(thinking_level=ThinkingLevel.MEDIUM),
            )
        except Exception as e:
            logger.warning(f"Source code verification pass failed: {e}")
            raise

        findings: list[ToolSourceCodeFinding] = []
        for llm_finding in verified_response.findings:
            tier = 1 if llm_finding.finding_type_id.value.startswith("t1") else 2
            severity = _get_source_code_security_severity(llm_finding.finding_type_id, is_remote)
            cwe = _get_source_code_security_cwe(llm_finding.finding_type_id)

            findings.append(
                ToolSourceCodeFinding(
                    finding_id=llm_finding.finding_id,
                    finding_type_id=llm_finding.finding_type_id.value,
                    finding_type_name=llm_finding.finding_type_name.value,
                    tier=tier,
                    severity=severity.value,
                    confidence=llm_finding.confidence.value,
                    affected_tools=llm_finding.affected_tools,
                    cwe=cwe.value if cwe else None,
                    explanation=llm_finding.explanation,
                    remediation=llm_finding.remediation,
                    taint_flow=llm_finding.taint_flow.model_dump() if llm_finding.taint_flow else None,
                )
            )
        return findings


class ToolAnalysisExtractor(BaseExtractor):
    """Runs tool metadata security analysis and nests source code taint flow analysis."""

    name = "tool_analysis"
    version = "1.0"
    cache_key_fn = staticmethod(strip_cache_noise)

    ALLOWED_EXTS = {
        "*.ts", "*.tsx", "*.js", "*.jsx", "*.mjs", "*.cjs",
        "*.py", "*.rs", "*.go", "*.java", "*.json", "*.md",
        "*.cs", "*.swift", "*.kt", "*.kts", "*.php", "*.rb",
    }
    EXCLUDE_DIRS = {
        "node_modules/", ".git/", "dist/", "build/", "out/",
        ".next/", ".turbo/", ".vercel/", ".cache/", ".venv/",
        "coverage/", ".vscode/", "__tests__/", "test*/",
    }
    MAX_CODEBASE_TOKENS = 800000

    def __init__(
            self,
            cache_service,
            *,
            gh_token=None,
            gh_tokens=None,
            vertex_project_id=None,
            env=None,
    ):
        super().__init__(cache_service)
        self._gh_token = gh_token
        self._gh_tokens = gh_tokens
        self._vertex_project_id = vertex_project_id
        self._env = env

    async def _compute(self, subject: Any, **kwargs) -> Union[ToolAnalysisResult, DoNotCache[ToolAnalysisResult]]:
        repo_url = subject.get("repo_url") if isinstance(subject, dict) else None
        repo_path = subject.get("repo_path") if isinstance(subject, dict) else None
        is_local = subject.get("is_local", False) if isinstance(subject, dict) else False
        tools_raw = subject.get("tools") if isinstance(subject, dict) else None

        has_repo = repo_path is not None

        if not tools_raw and not has_repo:
            return ToolAnalysisResult(has_repo=False, is_local=is_local)

        # Convert raw tool dicts to ToolModel instances (live discovery)
        live_tools: Optional[list[ToolModel]] = None
        if tools_raw:
            live_tools = [
                _coerce_tool_model(t) if isinstance(t, dict) else t
                for t in tools_raw
            ]

        # Build/tag/enrich tools → always produces list[DeepToolModel]
        tools: Optional[list[DeepToolModel]] = None
        tree, codebase = "", ""
        try:
            if has_repo:
                tools, tree, codebase = await self._build_or_tag_tools(repo_url, repo_path, live_tools)
            elif live_tools:
                tools = await self._enrich_tools_deep(live_tools)
        except Exception as e:
            return DoNotCache(ToolAnalysisResult(has_repo=has_repo, is_local=is_local),
                              reason=f"LLM tool build/tag failed: {e}")

        if not tools:
            return ToolAnalysisResult(has_repo=has_repo, is_local=is_local)

        # Metadata security analysis
        try:
            tier1_findings, tier2_findings, tool_tags = await self._analyze_metadata_security(tools)
        except Exception as e:
            return DoNotCache(ToolAnalysisResult(
                has_repo=has_repo, is_local=is_local, tools=tools,
            ), reason=f"LLM metadata security analysis failed: {e}")

        # Source code security analysis (reuses codebase already ingested above)
        tool_source_code_analysis = None

        if not has_repo:
            tool_source_code_analysis = ToolSourceCodeAnalysisResult(
                has_repo=False,
                tools=tools,
                tool_tags=tool_tags,
            )

        if has_repo:
            tool_source_code_analysis_ext = ToolSourceCodeAnalysisExtractor(
                self._cache_service,
                vertex_project_id=self._vertex_project_id,
                env=self._env,
            )
            tool_source_code_analysis = await tool_source_code_analysis_ext.extract(
                {
                    "has_repo": has_repo,
                    "is_local": is_local,
                    "tools": tools,
                    "tool_tags": tool_tags,
                    "tree": tree,
                    "codebase": codebase,
                }
            )

        return ToolAnalysisResult(
            has_repo=has_repo,
            is_local=is_local,
            tools=tools,
            tier1_findings=tier1_findings,
            tier2_findings=tier2_findings,
            tool_tags=tool_tags,
            tool_source_code_analysis=tool_source_code_analysis,
        )

    async def _build_or_tag_tools(
            self,
            repo_url: Optional[str],
            repo_path: str,
            tools: Optional[list[ToolModel]],
    ) -> tuple[Optional[list[DeepToolModel]], str, str]:
        """Build tools from source or tag existing tools with source-code-derived tags.

        Returns (tools, tree, codebase) so the ingested codebase can be reused downstream.
        """
        langfuse_client = get_client()

        _, tree, codebase = await ingest_async(
            source=repo_path,
            include_patterns=self.ALLOWED_EXTS,
            exclude_patterns=self.EXCLUDE_DIRS,
            include_gitignored=True,
        )

        gemini = GeminiVertexLLM(
            model="google/gemini-3-flash-preview",
            project_id=self._vertex_project_id,
            provider="gemini-vertex",
        )

        tagged_tools: Optional[list[ToolModel] | list[SourceConstructedToolModel]] = None

        if tools is None:
            # Build full tool dump + tags from source
            prompt = langfuse_client.get_prompt(
                "tool-src-code-construction-and-tagging", label=self._env
            )

            readme = await self._fetch_readme(repo_url, repo_path)
            codebase_truncated = self._truncate_to_tokens(codebase, self.MAX_CODEBASE_TOKENS)

            try:
                response: SourceCodeToolDumpAndTagsLLMResponseFormat = await gemini.agenerate(
                    messages=prompt.compile(
                        readme=readme or "(README missing or not supplied.)",
                        source_code=codebase_truncated,
                    ),
                    response_format=SourceCodeToolDumpAndTagsLLMResponseFormat,
                    max_tokens=-1,
                    thinking_config=ThinkingConfig(thinking_level=ThinkingLevel.MEDIUM),
                )
            except Exception as e:
                logger.warning(f"Tool dump construction failed: {e}")
                raise

            if not response.tools:
                return None, tree, codebase

            tagged_tools = response.tools
        else:
            # Tag existing tools
            tools_dump = json.dumps([t.model_dump() for t in tools])
            tag_prompt = langfuse_client.get_prompt(
                "tool-tagging-src-code-analysis", label=self._env
            )

            try:
                tag_response: ToolSrcCodeTagsLLMResponseFormat = await gemini.agenerate(
                    messages=tag_prompt.compile(tools_dump=tools_dump, source_code=codebase),
                    response_format=ToolSrcCodeTagsLLMResponseFormat,
                    max_tokens=-1,
                    thinking_config=ThinkingConfig(thinking_level=ThinkingLevel.MEDIUM),
                )
            except Exception as e:
                logger.warning(f"Tool tagging failed: {e}")
                raise

            if tag_response and tag_response.tool_tags:
                tagged_tools = self._merge_src_tags_into_tools(tools, tag_response.tool_tags)
            else:
                tagged_tools = tools

        deep_tools = await self._enrich_tools_deep(tagged_tools)
        return deep_tools, tree, codebase

    async def _fetch_readme(
            self,
            repo_url: Optional[str],
            repo_path: Optional[str] = None,
    ) -> Optional[str]:
        """Fetch the README for a repo, source-agnostic.

        Prefers the local filesystem (works for git clones and unpacked
        marketplace .vsix trees alike); falls back to the GitHub API for the
        monorepo-subdirectory case where the cloned tree might not be at the
        right depth.
        """
        if repo_path:
            root = Path(repo_path)
            for filename in ("README.md", "README.markdown", "README.rst", "README.txt", "README"):
                candidate = root / filename
                if candidate.is_file():
                    try:
                        return candidate.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        pass
        if not repo_url:
            return None
        gh = GitHubClient(gh_token=self._gh_token, gh_tokens=self._gh_tokens)
        owner, repo, full_ref = GitHubClient.parse_github_url(repo_url)
        if not owner or not repo:
            return None
        # For monorepo paths, try subdirectory README first, then fall back to root
        if full_ref:
            for _branch, sub_path in GitHubClient.split_branch_path(full_ref):
                if sub_path:
                    readme = await gh.get_readme(owner, repo, path=sub_path)
                    if readme:
                        return readme
        return await gh.get_readme(owner, repo)

    async def _analyze_metadata_security(
            self, tools: list[DeepToolModel]
    ) -> tuple[list[ToolPoisoningFinding], list[HighRiskCapabilityFinding], list[ToolTagInfo]]:
        """Analyze tool metadata for poisoning patterns and high-risk capabilities."""
        if not tools:
            return [], [], []

        langfuse_client = get_client()
        prompt = langfuse_client.get_prompt("tool-metadata-security-analysis", label=self._env)
        gemini = GeminiVertexLLM(
            model="google/gemini-3-flash-preview",
            project_id=self._vertex_project_id,
            provider="gemini-vertex",
        )

        try:
            result: MetadataSecurityLLMResponseFormat = await gemini.agenerate(
                messages=prompt.compile(tools=tools),
                response_format=MetadataSecurityLLMResponseFormat,
                max_tokens=-1,
            )
        except Exception as e:
            logger.warning(f"Tool metadata security analysis failed: {e}")
            raise

        # Build ToolTagInfo from source-code tags already merged onto tool objects
        tool_tags = [
            ToolTagInfo(
                tool_name=tool.name,
                capability_tags=[t if isinstance(t, str) else t.value for t in getattr(tool, "capability_tags", [])],
                input_tags=[t if isinstance(t, str) else t.value for t in getattr(tool, "input_tags", [])],
                output_tags=[t if isinstance(t, str) else t.value for t in getattr(tool, "output_tags", [])],
            )
            for tool in tools
        ]

        return result.tier1_findings, result.tier2_findings, tool_tags

    async def _enrich_tools_deep(
            self,
            tools: list[ToolModel] | list[SourceConstructedToolModel],
    ) -> list[DeepToolModel]:
        """Enrich tools with deep fields via LLM (one call)."""
        langfuse_client = get_client()
        prompt = langfuse_client.get_prompt("deep-tool-analysis", label=self._env)
        gemini_lite = GeminiVertexLLM(
            model="google/gemini-2.5-flash-lite",
            project_id=self._vertex_project_id,
            provider="gemini-vertex",
        )
        response: DeepToolAnalysisLLMResponseFormat = await gemini_lite.agenerate(
            messages=prompt.compile(tools=tools),
            response_format=DeepToolAnalysisLLMResponseFormat,
            max_tokens=-1,
            thinking_config=ThinkingConfig(thinking_budget=2048),
        )
        results = cast(dict[str, ExtraToolDetailsLLMResponseFormat], cast(object, {r.name: r for r in response.tools}))
        enriched = []
        for tool in tools:
            deep = results.get(tool.name)
            raw_schema = getattr(tool, "inputSchema", {}) or {}
            if isinstance(raw_schema, BaseModel):
                raw_schema = raw_schema.model_dump()
            enriched.append(DeepToolModel(
                # title=getattr(tool, "title", None),
                name=tool.name,
                description=tool.description,
                inputSchema=JSONSchemaObject(
                    type=raw_schema.get("type", "object"),
                    properties=raw_schema.get("properties", {}),
                    required=raw_schema.get("required"),
                ),
                # icons=[
                #     IconObject(
                #         src=getattr(icon, "src", None),
                #         mimeType=getattr(icon, "mimeType", None),
                #         sizes=getattr(icon, "sizes", None),
                #     )
                #     for icon in raw_icons
                # ] if raw_icons else None,
                # outputSchema=JSONSchemaObject(
                #     type=raw_output_schema.get("type", "object"),
                #     properties=raw_output_schema.get("properties", {}),
                #     required=raw_output_schema.get("required"),
                # ) if raw_output_schema else None,
                # annotations=ToolAnnotationsObject(
                #     title=getattr(raw_annotations, "title", None),
                #     readOnlyHint=getattr(raw_annotations, "readOnlyHint", None),
                #     destructiveHint=getattr(raw_annotations, "destructiveHint", None),
                #     idempotentHint=getattr(raw_annotations, "idempotentHint", None),
                #     openWorldHint=getattr(raw_annotations, "openWorldHint", None),
                # ) if raw_annotations else None,
                operation_kind=deep.operation_kind if deep else OperationKindEnum.READ,
                destructive_level=deep.destructive_level if deep else DestructiveLevelEnum.LOW,
                dangerous_params=deep.dangerous_params if deep else [],
                human_readable_description=deep.human_readable_description if deep else (tool.description or ""),
                capability_tags=getattr(tool, "capability_tags", []),
                input_tags=getattr(tool, "input_tags", []),
                output_tags=getattr(tool, "output_tags", []),
            ))
        return enriched

    @staticmethod
    def _truncate_to_tokens(text: str, target_tokens: int) -> str:
        encoding = tiktoken.get_encoding("cl100k_base")
        token_count = len(encoding.encode(text, disallowed_special=()))
        while token_count > target_tokens:
            truncate_ratio = target_tokens / token_count
            approximate_char_length = int(len(text) * truncate_ratio)
            text = text[:approximate_char_length]
            token_count = len(encoding.encode(text, disallowed_special=()))
        return text

    @staticmethod
    def _merge_src_tags_into_tools(
            tools: list[ToolModel], tags: list[ToolSrcCodeNamedTagLLMResponseFormat]
    ) -> list[ToolModel]:
        tags_by_name = {t.tool_name: t for t in tags}
        for tool in tools:
            if tag := tags_by_name.get(tool.name):
                tool.capability_tags = list(tag.capability_tags)
                tool.input_tags = list(tag.input_tags)
                tool.output_tags = list(tag.output_tags)
        return tools


__all__ = [
    "ToolAnalysisExtractor",
    "ToolSourceCodeAnalysisExtractor",
    "ToolAnalysisResult",
    "ToolSourceCodeAnalysisResult",
    "ToolPoisoningFinding",
    "HighRiskCapabilityFinding",
    "ToolSourceCodeFinding",
    "ToolTagInfo",
]
