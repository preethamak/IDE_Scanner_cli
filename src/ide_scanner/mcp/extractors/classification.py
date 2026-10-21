"""ClassificationExtractor — determines officiality and hosting classification."""

import json
import logging
from typing import Any, Literal, Optional, Union

import tiktoken
from gitingest import ingest_async
from google.genai.types import Tool, GoogleSearch, UrlContext
from langfuse import get_client
from loguru import logger
from pydantic import BaseModel, Field

from ..types import (
    OfficialityFalseEnum,
    OfficialityTrueEnum,
)
from ..types import OfficialityEnum
from ..base import BaseExtractor, DoNotCache
from ..llm import GeminiVertexLLM
from .repo_metadata import RepoMetadataExtractor, RepoMetadataResult
from .utils import strip_cache_noise

logger.disable("gitingest")
logging.getLogger("gitingest").disabled = True


# --- LLM response models ---

class IntendedSAASLLMResponseFormat(BaseModel):
    saas_name: str = Field(description="Name of the SAAS application")
    confidence: float = Field(description="Confidence of the classification")
    evidence: list[str] = Field(description="List of evidence for the classification")
    notes: str = Field(description="Reasoning for the classification")


OfficialityEnumLiteral = Literal[
    "OFFICIAL_SITE_LINKS_REPO",
    "OFFICIAL_GITHUB_ORG_CONFIRMED",
    "OFFICIAL_SITE_OWNS_PRODUCT",
    "OFFICIAL_API_DOMAIN_AND_DOMAIN_OVERLAP",
    "LEGAL_OWNERSHIP_CONFIRMED",
    "DEFAULT_UNOFFICIAL",
    "NO_OFFICIAL_SITE_REPO_LINK",
    "GITHUB_ORG_NOT_CONFIRMED",
    "OFFICIAL_DOMAIN_OVERLAP_MISSING",
    "THIRD_PARTY_API_OR_DOCS_DOMAIN",
    "EXPLICIT_NON_OWNERSHIP_CONFIRMED",
]


class ObservedInputDomainsLLMResponseFormat(BaseModel):
    org_url_domain: Optional[str] = Field(description="Domain from org_url")
    org_domains_registrable: list[str] = Field(
        description="Registrable domains from org_details.domains"
    )
    evidence_url_registrable: list[str] = Field(
        description="Registrable domains extracted from evidence URLs"
    )


class OfficialSaasDomainsLLMResponseFormat(BaseModel):
    registrable: list[str] = Field(description="Official registrable domains for the SaaS")
    supporting_urls: list[str] = Field(description="URLs that support these domains")


class KeyEvidenceLLMResponseFormat(BaseModel):
    type: str = Field(
        description="Type of evidence (e.g., 'github_org_validation', 'first_party_ownership', 'domain_overlap')"
    )
    detail: str = Field(description="Detailed description of the evidence")
    url: str = Field(description="Supporting URL for this evidence")


class MatchSAASLLMResponseFormat(BaseModel):
    repo_url: Optional[str] = Field(default=None, description="Repository URL being analyzed")
    saas_name: Optional[str] = Field(default=None, description="Name of the SaaS")
    company_org_url: Optional[str] = Field(default=None, description="Company organization URL")
    company_registrable_domain: Optional[str] = Field(
        default=None, description="Company's registrable domain"
    )
    observed_input_domains: Optional[ObservedInputDomainsLLMResponseFormat] = Field(
        default=None, description="Domains observed from input"
    )
    official_saas_domains: Optional[OfficialSaasDomainsLLMResponseFormat] = Field(
        default=None, description="Official SaaS domains found"
    )
    checks_performed: Optional[list[str]] = Field(
        default=None, description="List of search queries and checks performed"
    )
    key_evidence: Optional[list[KeyEvidenceLLMResponseFormat]] = Field(
        default=None, description="Structured key evidence for the match"
    )
    officiality_enum: OfficialityEnumLiteral = Field(
        description="Officiality classification enum member name from OfficialityTrueEnum or OfficialityFalseEnum"
    )
    confidence: float = Field(description="Confidence score (0.0-1.0)")
    reasoning: str = Field(description="Detailed reasoning for the classification")


class OfficialityContextModel(BaseModel):
    repo_url: str = Field(description="Repository URL being analyzed")
    org_details: dict = Field(description="Organization details from GitHub")
    intended_saas: IntendedSAASLLMResponseFormat = Field(description="Intended SaaS classification")


class ClassificationResult(BaseModel):
    """Classification of the MCP server: officiality, locality, and source availability."""

    officiality: OfficialityEnum
    is_local: bool
    has_repo: bool
    message: Optional[str] = None
    repo_metadata: Optional[RepoMetadataResult] = None


class ClassificationExtractor(BaseExtractor):
    """Determines officiality and hosting classification.

    Depends on RepoMetadataExtractor (resolved via shared cache).
    """

    name = "classification"
    version = "1.0"
    cache_key_fn = staticmethod(strip_cache_noise)

    def __init__(
            self,
            cache_service,
            *,
            gh_token=None,
            gh_tokens=None,
            vertex_project_id=None,
            google_api_key=None,
            google_search_cx=None,
            env=None,
    ):
        super().__init__(cache_service)
        self._gh_token = gh_token
        self._gh_tokens = gh_tokens
        self._vertex_project_id = vertex_project_id
        self._google_api_key = google_api_key
        self._google_search_cx = google_search_cx
        self._env = env

    async def _compute(
            self, subject: Any, **kwargs
    ) -> Union[tuple[ClassificationResult, Optional[dict[str, Any]]], DoNotCache[tuple[ClassificationResult, None]]]:
        # Self-resolving dependency: fetch repo metadata via cache
        repo_metadata_ext = RepoMetadataExtractor(
            self._cache_service, gh_token=self._gh_token, gh_tokens=self._gh_tokens
        )
        repo_metadata: RepoMetadataResult = await repo_metadata_ext.extract(subject)

        repo_url = subject.get("repo_url") if isinstance(subject, dict) else None
        is_local = subject.get("is_local", False) if isinstance(subject, dict) else False
        has_repo = repo_url is not None

        # Skip LLM classification if a human has already verified officiality
        hitl_officiality = subject.get("hitl_officiality") if isinstance(subject, dict) else None
        if hitl_officiality is not None:
            if hitl_officiality == OfficialityEnum.OFFICIAL:
                hitl_message = OfficialityTrueEnum.HUMAN_VERIFIED_OFFICIAL.value
            elif hitl_officiality == OfficialityEnum.THIRDPARTY:
                hitl_message = OfficialityTrueEnum.HUMAN_VERIFIED_THIRDPARTY.value
            else:
                hitl_message = OfficialityFalseEnum.HUMAN_VERIFIED_UNOFFICIAL.value

            return (
                ClassificationResult(
                    officiality=hitl_officiality,
                    is_local=is_local,
                    has_repo=has_repo,
                    message=hitl_message,
                    repo_metadata=repo_metadata,
                ),
                None,
            )

        if not has_repo:
            return (
                ClassificationResult(
                    officiality=OfficialityEnum.UNOFFICIAL,
                    is_local=is_local,
                    has_repo=False,
                    message=OfficialityFalseEnum.DEFAULT_UNOFFICIAL.value,
                    repo_metadata=repo_metadata,
                ),
                None,
            )

        # Classify intended SaaS from source code
        try:
            intended_saas = await self._classify_intended_saas(repo_url)
        except Exception as e:
            logger.warning(f"LLM intended SaaS classification failed: {e}")
            return DoNotCache((
                ClassificationResult(
                    officiality=OfficialityEnum.UNOFFICIAL,
                    is_local=is_local,
                    has_repo=has_repo,
                    message=OfficialityFalseEnum.DEFAULT_UNOFFICIAL.value,
                    repo_metadata=repo_metadata,
                ),
                None,
            ), reason=f"LLM intended SaaS classification failed: {e}")

        if intended_saas.saas_name.lower() == "unknown":
            return (
                ClassificationResult(
                    officiality=OfficialityEnum.UNOFFICIAL,
                    is_local=is_local,
                    has_repo=has_repo,
                    message=OfficialityFalseEnum.DEFAULT_UNOFFICIAL.value,
                    repo_metadata=repo_metadata,
                ),
                None,
            )

        # Build org details dict from repo metadata
        org_details = {
            "verified": repo_metadata.org_verified,
            "org_url": repo_metadata.org_url,
            "description": repo_metadata.org_description,
            "topics": repo_metadata.org_topics,
            "domains": repo_metadata.org_domains,
        }

        officiality_context = OfficialityContextModel(
            repo_url=repo_url,
            org_details=org_details,
            intended_saas=intended_saas,
        )

        try:
            match_result = await self._match_saas(officiality_context)
        except Exception as e:
            logger.warning(f"LLM match SaaS classification failed: {e}")
            return DoNotCache((
                ClassificationResult(
                    officiality=OfficialityEnum.UNOFFICIAL,
                    is_local=is_local,
                    has_repo=has_repo,
                    message=OfficialityFalseEnum.DEFAULT_UNOFFICIAL.value,
                    repo_metadata=repo_metadata,
                ),
                None,
            ), reason=f"LLM match SaaS classification failed: {e}")
        classification_artifact = {
            "org_details": org_details,
            "intended_saas": intended_saas.model_dump(mode="json"),
            "match_saas": match_result.model_dump(mode="json"),
        }

        # Map result to OfficialityEnum
        if match_result.officiality_enum == "DEFAULT_UNOFFICIAL":
            return (
                ClassificationResult(
                    officiality=OfficialityEnum.UNOFFICIAL,
                    is_local=is_local,
                    has_repo=has_repo,
                    message=OfficialityFalseEnum.DEFAULT_UNOFFICIAL.value,
                    repo_metadata=repo_metadata,
                ),
                classification_artifact,
            )

        if match_result.officiality_enum in OfficialityTrueEnum.__members__:
            return (
                ClassificationResult(
                    officiality=OfficialityEnum.OFFICIAL,
                    is_local=is_local,
                    has_repo=has_repo,
                    message=OfficialityTrueEnum[match_result.officiality_enum].value,
                    repo_metadata=repo_metadata,
                ),
                classification_artifact,
            )

        try:
            enum_value = OfficialityFalseEnum[match_result.officiality_enum]
        except KeyError:
            enum_value = OfficialityFalseEnum.DEFAULT_UNOFFICIAL

        return (
            ClassificationResult(
                officiality=OfficialityEnum.UNOFFICIAL,
                is_local=is_local,
                has_repo=has_repo,
                message=enum_value.value,
                repo_metadata=repo_metadata,
            ),
            classification_artifact,
        )

    async def _classify_intended_saas(self, repo_url: str) -> IntendedSAASLLMResponseFormat:
        """Use gitingest + LLM to identify target SaaS."""
        langfuse_client = get_client()
        prompt = langfuse_client.get_prompt("intended-saas-indentification", label=self._env)

        gemini_lite = GeminiVertexLLM(
            model="google/gemini-2.5-flash-lite",
            project_id=self._vertex_project_id,
        )

        include_patterns = {"*.py", "*.js", "*.ts", "*.go", "*.rs", "*.java", "README*", "*.md"}
        summary, tree, content = await ingest_async(
            repo_url, include_patterns=include_patterns, include_gitignored=True
        )

        ingested_data_str = json.dumps({"summary": summary, "tree": tree, "content": content})
        ingested_data_str = self._truncate_text(ingested_data_str, 800_000)

        result = await gemini_lite.agenerate(
            messages=prompt.compile(codebase_content=ingested_data_str),
            response_format=IntendedSAASLLMResponseFormat,
            max_tokens=8192,
        )
        return result

    async def _match_saas(self, officiality_context: OfficialityContextModel) -> MatchSAASLLMResponseFormat:
        """Use Google Search + LLM to verify officiality."""
        langfuse_client = get_client()
        match_prompt = langfuse_client.get_prompt(
            "match-saas-to-company-domains", label=self._env
        )
        normalize_prompt = langfuse_client.get_prompt(
            "normalize-saas-company-domain-match", label=self._env
        )

        gemini = GeminiVertexLLM(
            model="google/gemini-3-flash-preview",
            project_id=self._vertex_project_id,
        )
        gemini_lite = GeminiVertexLLM(
            model="google/gemini-2.5-flash-lite",
            project_id=self._vertex_project_id,
        )

        google_search_tool = Tool(google_search=GoogleSearch())
        url_context_tool = Tool(url_context=UrlContext())

        # Research with tools
        raw_analysis = await gemini.agenerate(
            messages=match_prompt.compile(officiality_context=officiality_context),
            max_tokens=8192,
            tools=[google_search_tool, url_context_tool],
        )
        if not raw_analysis:
            raise ValueError("LLM returned empty raw analysis for match_saas")

        # Normalize into structured format
        structured_result = await gemini_lite.agenerate(
            messages=normalize_prompt.compile(match_saas_result=raw_analysis),
            response_format=MatchSAASLLMResponseFormat,
            max_tokens=8192,
        )
        return structured_result

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
    "ClassificationExtractor",
    "ClassificationResult",
]
