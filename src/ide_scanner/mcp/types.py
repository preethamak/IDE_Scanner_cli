from __future__ import annotations

from enum import Enum


class StatusEnum(str, Enum):
    SUCCESS = "success"
    WARNING = "warning"
    FAILURE = "failure"
    SKIPPED = "skipped"
    ERROR = "error"
    UNKNOWN = "unknown"


class VetoLevelEnum(str, Enum):
    WARNING = "warning"
    FAILURE = "failure"


class OfficialityEnum(str, Enum):
    OFFICIAL = "official"
    UNOFFICIAL = "unofficial"
    THIRDPARTY = "thirdparty"


class AuthModeEnum(str, Enum):
    OAUTH = "oauth"
    PAT = "pat"
    API_KEY = "api_key"
    UNKNOWN = "unknown"
    NO_AUTH = "no_auth"


class AuthSummaryEnum(str, Enum):
    OAUTH = "oauth"
    OAUTH_API_KEY = "oauth_api_key"
    OAUTH_PAT = "oauth_pat"
    OAUTH_API_KEY_PAT = "oauth_api_key_pat"
    API_KEY = "api_key"
    PAT = "pat"
    API_KEY_PAT = "api_key_pat"
    NO_AUTH = "no_auth"
    UNKNOWN = "unknown"


class OfficialityTrueEnum(str, Enum):
    HUMAN_VERIFIED_OFFICIAL = "human_verified_official"
    HUMAN_VERIFIED_THIRDPARTY = "human_verified_thirdparty"
    OFFICIAL_SITE_LINKS_REPO = "official_site_links_repo"
    OFFICIAL_GITHUB_ORG_CONFIRMED = "official_github_org_confirmed"
    OFFICIAL_SITE_OWNS_PRODUCT = "official_site_owns_product"
    OFFICIAL_API_DOMAIN_AND_DOMAIN_OVERLAP = "official_api_domain_and_domain_overlap"
    LEGAL_OWNERSHIP_CONFIRMED = "legal_ownership_confirmed"


class OfficialityFalseEnum(str, Enum):
    DEFAULT_UNOFFICIAL = "default_unofficial"
    HUMAN_VERIFIED_UNOFFICIAL = "human_verified_unofficial"
    UNOFFICIAL_URL = "unofficial_url"
    UNOFFICIAL_PACKAGE = "unofficial_package"
    UNOFFICIAL_NO_REPO_URL = "unofficial_no_repo_url"
    AWAITING_HITL = "awaiting_hitl"
    NO_OFFICIAL_SITE_REPO_LINK = "no_official_site_repo_link"
    GITHUB_ORG_NOT_CONFIRMED = "github_org_not_confirmed"
    OFFICIAL_DOMAIN_OVERLAP_MISSING = "official_domain_overlap_missing"
    THIRD_PARTY_API_OR_DOCS_DOMAIN = "third_party_api_or_docs_domain"
    EXPLICIT_NON_OWNERSHIP_CONFIRMED = "explicit_non_ownership_confirmed"


class PackageSourceEnum(str, Enum):
    DOCKER = "docker"
    NPX = "npx"
    NODE = "node"
    PYTHON = "python"
    UVX = "uvx"
    PIPX = "pipx"
    UV = "uv"
    MISC = "misc"
