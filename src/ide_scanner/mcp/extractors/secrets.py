"""SecretsExtractor — gitleaks + LLM judge for secrets detection."""

import json
import logging
from pathlib import Path
from typing import Any, Optional, Union

from langfuse import get_client
from pydantic import BaseModel, ConfigDict, Field

from ..process import run_subprocess_exec
from ..base import BaseExtractor, DoNotCache
from ..llm import GeminiVertexLLM
from .utils import strip_cache_noise

logger = logging.getLogger(__name__)


# --- LLM response models ---

class GitLeaksLLMContextModel(BaseModel):
    index: int
    file: str
    match: str
    secret: str
    code: str


class GitLeaksLeakVerdictLLMResponseFormat(BaseModel):
    index: int = Field(description="The index of the leaked credential's object.")
    is_leak: bool = Field(description="Whether the credential is a real leak or false positive.")
    reason: str = Field(description="Justification for the verdict.")
    identified_credential: Optional[str] = Field(
        default=None,
        description="For generic detections, the full friendly credential name if identified.",
    )


class GitLeaksLLMJudgeLLMResponseFormat(BaseModel):
    leaks: list[GitLeaksLeakVerdictLLMResponseFormat]


class SecretFinding(BaseModel):
    """Typed wrapper for the legacy gitleaks finding payload."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    rule_id: str = Field(default="unknown credential", alias="RuleID")
    original_rule_id: Optional[str] = Field(default=None, alias="OriginalRuleID")
    file: str = Field(default="", alias="File")
    start_line: Optional[int] = Field(default=None, alias="StartLine")
    end_line: Optional[int] = Field(default=None, alias="EndLine")
    match: str = Field(default="", alias="Match")


class SecretsScanResult(BaseModel):
    """Results of secrets detection scan."""

    has_repo: bool = False
    secrets_found: list[SecretFinding] = Field(default_factory=list)
    secrets_count: int = 0
    error: Optional[str] = None


# --- Credential naming maps ---

SERVICE_MAP = {
    "aws": "AWS",
    "github": "GitHub",
    "gitlab": "GitLab",
    "slack": "Slack",
    "twitter": "Twitter (X)",
    "gcp": "Google Cloud",
    "cloudflare": "Cloudflare",
    "telegram": "Telegram",
    "huggingface": "Hugging Face",
    "perplexity": "Perplexity",
    "notion": "Notion",
    "hubspot": "HubSpot",
    "linkedin": "LinkedIn",
    "algolia": "Algolia",
    "atlassian": "Atlassian",
    "cohere": "Cohere",
    "kubernetes": "Kubernetes",
    "azure": "Azure",
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "stripe": "Stripe",
    "twilio": "Twilio",
    "sendgrid": "SendGrid",
    "mailgun": "Mailgun",
    "datadog": "Datadog",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "postgres": "PostgreSQL",
    "mysql": "MySQL",
}

TYPE_MAP = {
    "api-key": "API key",
    "access-token": "Access Token",
    "api-token": "API Token",
    "bot-token": "Bot Token",
    "pat": "Personal Access Token",
    "client-id": "Client ID",
    "client-secret": "Client Secret",
    "private-key": "Private Key",
    "auth-header": "Authentication Header",
    "secret": "Secret",
    "jwt": "JSON Web Token (JWT)",
    "jwt-base64": "base64-encoded JWT",
    "webhook": "Webhook",
    "password": "Password",
    "credentials": "Credentials",
    "token": "Token",
    "key": "Key",
}


class SecretsExtractor(BaseExtractor):
    """Runs gitleaks + LLM judge for secrets detection."""

    name = "secrets_scan"
    version = "1.0"
    cache_key_fn = staticmethod(strip_cache_noise)

    def __init__(self, cache_service, *, vertex_project_id=None, env=None):
        super().__init__(cache_service)
        self._vertex_project_id = vertex_project_id
        self._env = env

    async def _compute(self, subject: Any, **kwargs) -> Union[SecretsScanResult, DoNotCache[SecretsScanResult]]:
        repo_path = subject.get("repo_path") if isinstance(subject, dict) else None
        if not repo_path:
            return SecretsScanResult(has_repo=False)

        # Run gitleaks
        gitleaks_json = await self._run_gitleaks(repo_path)
        if gitleaks_json is None:
            return DoNotCache(
                SecretsScanResult(has_repo=True, secrets_count=0, error="gitleaks subprocess failed"),
                reason="gitleaks subprocess failed",
            )

        if len(gitleaks_json) == 0:
            return SecretsScanResult(has_repo=True, secrets_count=0)

        # Prepare LLM context
        llm_context = self._prepare_llm_context(gitleaks_json, repo_path)
        if not llm_context:
            return SecretsScanResult(has_repo=True, secrets_count=0)

        # Run LLM judge
        confirmed_findings = await self._run_llm_judge(gitleaks_json, llm_context)
        if confirmed_findings is None:
            return DoNotCache(
                SecretsScanResult(has_repo=True, secrets_count=0, error="LLM judge failed"),
                reason="LLM judge call failed",
            )

        return SecretsScanResult(
            has_repo=True,
            secrets_found=confirmed_findings,
            secrets_count=len(confirmed_findings),
        )

    async def _run_gitleaks(self, repo_path: str, timeout: int = 60) -> Optional[list[dict]]:
        """Run gitleaks detect and parse JSON output."""
        args = [
            "gitleaks", "detect", "--source", repo_path,
            "--no-banner", "--report-format=json", "--report-path=-",
        ]
        try:
            stdout, stderr, returncode = await run_subprocess_exec(args=args, timeout=timeout)
        except Exception as e:
            logger.warning(f"Failed to run gitleaks: {e}")
            return None

        try:
            return json.loads(stdout)
        except json.JSONDecodeError as e:
            logger.warning(f"Gitleaks produced invalid JSON output: {e}")
            return None

    @staticmethod
    def _prepare_llm_context(
        final_json: list[dict],
        repo_root: str,
        max_tokens: int = 100_000,
        context_lines: int = 5,
    ) -> list[dict]:
        """Extract code snippets around each finding for LLM judge."""
        root = Path(repo_root)
        out: list[dict] = []
        total_tokens = 0

        for idx, f in enumerate(final_json):
            rel = str(f.get("File") or "")
            if rel.lower().endswith(".md"):
                continue

            secret = str(f.get("Secret") or "")
            s_lower = secret.lower()
            if "test" in s_lower or "12345" in secret:
                continue

            start_line = f.get("StartLine")
            end_line = f.get("EndLine")
            if start_line is None or end_line is None:
                continue

            code_snippet = ""
            fp = root / rel
            if fp.is_file():
                try:
                    with fp.open("r", encoding="utf-8", errors="replace") as fh:
                        context_start = max(1, start_line - context_lines)
                        context_end = end_line + context_lines

                        for _ in range(context_start - 1):
                            fh.readline()

                        context_window = []
                        lines_to_read = context_end - context_start + 1
                        for _ in range(lines_to_read):
                            line = fh.readline()
                            if not line:
                                break
                            context_window.append(line)

                        actual_end = context_start + len(context_window) - 1
                        code_snippet = f"... (lines {context_start}-{actual_end}) ...\n"
                        code_snippet += "".join(context_window)
                except Exception:
                    code_snippet = ""

            candidate = {
                "index": idx,
                "file": rel,
                "match": str(f.get("Match") or ""),
                "secret": secret,
                "code": code_snippet,
            }

            candidate_tokens = len(candidate["code"]) // 3
            if total_tokens + candidate_tokens > max_tokens:
                break

            out.append(candidate)
            total_tokens += candidate_tokens

        return out

    async def _run_llm_judge(
        self, final_json: list[dict], llm_context: list[dict]
    ) -> Optional[list[SecretFinding]]:
        """Use LLM to filter false positives from gitleaks findings."""
        langfuse_client = get_client()
        prompt = langfuse_client.get_prompt("gitleaks-llm-judge", label=self._env)
        llm = GeminiVertexLLM(
            model="google/gemini-3-flash-preview",
            project_id=self._vertex_project_id,
        )

        try:
            response: GitLeaksLLMJudgeLLMResponseFormat = await llm.agenerate(
                messages=prompt.compile(findings_json=llm_context),
                response_format=GitLeaksLLMJudgeLLMResponseFormat,
                max_tokens=16384,
            )
        except Exception as e:
            logger.warning(f"Secrets detection LLM judge failed: {e}")
            return None


        # Filter to confirmed leaks with valid indices
        confirmed: list[SecretFinding] = []
        for m in response.leaks:
            if m.is_leak and m.index < len(final_json):
                finding = final_json[m.index].copy()
                original_rule_id = finding.get("RuleID", "unknown")
                finding["OriginalRuleID"] = original_rule_id

                if m.identified_credential and original_rule_id.startswith("generic-"):
                    finding["RuleID"] = m.identified_credential
                else:
                    finding["RuleID"] = self._friendly_name(original_rule_id)

                confirmed.append(SecretFinding.model_validate(finding))

        return confirmed

    @staticmethod
    def _friendly_name(rule_id: str) -> str:
        """Generate a friendly message from a gitleaks rule ID."""
        if not rule_id or rule_id == "unknown":
            return "unknown credential"

        if "-" not in rule_id:
            service = SERVICE_MAP.get(rule_id.lower(), rule_id.title())
            return f"{service} credential"

        if rule_id.startswith("generic-"):
            type_part = rule_id.replace("generic-", "")
            cred = TYPE_MAP.get(type_part, type_part.replace("-", " "))
            return f"{cred} (unknown service)"

        parts = rule_id.split("-")

        for i in range(len(parts), 0, -1):
            suffix = "-".join(parts[-i:])
            if suffix in TYPE_MAP:
                service_key = "-".join(parts[:-i]) if i < len(parts) else rule_id
                service = SERVICE_MAP.get(service_key, service_key.replace("-", " ").title())
                cred = TYPE_MAP[suffix]
                return f"{service} {cred}"

        service = SERVICE_MAP.get(rule_id, rule_id.replace("-", " ").title())
        return f"{service} credential"


__all__ = [
    "SecretsExtractor",
    "SecretFinding",
    "SecretsScanResult",
]

