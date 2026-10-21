"""Lightweight async GitHub API client with token rotation."""

import base64
import logging
import re
from typing import Optional, Tuple

import httpx
from httpx import ConnectTimeout, HTTPStatusError

from ...token_rotation import TokenRotator

logger = logging.getLogger(__name__)


class GitHubClient:
    """Async GitHub API wrapper with token rotation support."""

    API_URL = "https://api.github.com"
    SCORECARD_URL = "https://api.scorecard.dev/projects/github.com"
    TIMEOUT = 10
    HEADERS = {
        "User-Agent": "mcp-risk-profiler/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
        "Accept": "application/vnd.github.v3+json",
    }

    def __init__(
        self,
        gh_token: Optional[str] = None,
        gh_tokens: Optional[list[str]] = None,
    ):
        assert not (gh_token and gh_tokens), "Only one of gh_token or gh_tokens can be provided."
        self._gh_token = gh_token
        self._token_rotator = TokenRotator(gh_tokens) if gh_tokens else None

    @property
    def token(self) -> Optional[str]:
        if self._token_rotator:
            return self._token_rotator.next_token()
        return self._gh_token

    def _auth_headers(self) -> dict[str, str]:
        headers = self.HEADERS.copy()
        token = self.token
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    @staticmethod
    def parse_github_url(repo_url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Parse GitHub URL into (owner, repo, full_ref).

        Handles URLs like:
        - https://github.com/owner/repo
        - https://github.com/owner/repo/tree/branch/path
        """
        match = re.match(r"https://github\.com/([^/]+)/([^/]+)(?:/(.*))?$", repo_url.strip())
        if not match:
            return None, None, None
        owner, repo, remainder = match.groups()
        full_ref = None
        if remainder and remainder.startswith("tree/"):
            ref = remainder[5:]
            if ref:
                full_ref = ref
        return owner, repo, full_ref

    @staticmethod
    def split_branch_path(ref: str) -> list[Tuple[Optional[str], Optional[str]]]:
        """Given a ref, return possible (branch, path) interpretations."""
        if not ref:
            return []
        parts = ref.split("/")
        interpretations: list[Tuple[Optional[str], Optional[str]]] = [(ref, None)]
        for i in range(len(parts) - 1, 0, -1):
            branch_part = "/".join(parts[:i])
            path_part = "/".join(parts[i:])
            interpretations.append((branch_part, path_part))
        return interpretations

    async def get_repo(self, owner: str, repo: str) -> Optional[dict]:
        """Fetch repository metadata."""

        headers = self._auth_headers()
        try:
            async with httpx.AsyncClient(headers=headers, timeout=self.TIMEOUT) as client:
                resp = await client.get(f"{self.API_URL}/repos/{owner}/{repo}")
                resp.raise_for_status()
                return resp.json()
        except (HTTPStatusError, ConnectTimeout, httpx.RequestError) as e:
            logger.warning(f"Failed to fetch repo {owner}/{repo} - {e}")
            return None

    async def get_latest_commit(self, owner: str, repo: str, full_ref: Optional[str] = None) -> Optional[dict]:
        """Fetch the latest commit (sha + date)."""

        if self.token is None:
            return None
        headers = self._auth_headers()
        try:
            async with httpx.AsyncClient(headers=headers, timeout=self.TIMEOUT) as client:
                if full_ref:
                    for branch, path in self.split_branch_path(full_ref):
                        params: dict[str, str | int] = {"per_page": 1}
                        if branch:
                            params["sha"] = branch
                        if path:
                            params["path"] = path
                        try:
                            resp = await client.get(
                                f"{self.API_URL}/repos/{owner}/{repo}/commits",
                                params=params,
                            )
                            resp.raise_for_status()
                            data = resp.json()
                            if data and isinstance(data, list):
                                c = data[0]
                                return {
                                    "sha": c.get("sha"),
                                    "date": ((c.get("commit") or {}).get("author") or {}).get("date"),
                                }
                        except HTTPStatusError as e:
                            if e.response.status_code in (404, 422):
                                continue
                            logger.warning(f"Failed to fetch latest commit for {owner}/{repo} - {e}")
                            return None
                else:
                    resp = await client.get(
                        f"{self.API_URL}/repos/{owner}/{repo}/commits",
                        params={"per_page": 1},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    if data and isinstance(data, list):
                        c = data[0]
                        return {
                            "sha": c.get("sha"),
                            "date": ((c.get("commit") or {}).get("author") or {}).get("date"),
                        }
        except (HTTPStatusError, ConnectTimeout, httpx.RequestError) as e:
            logger.warning(f"Failed to fetch latest commit for {owner}/{repo} - {e}")
        return None

    async def search_prs(self, owner: str, repo: str) -> Optional[int]:
        """Get count of open PRs."""

        headers = self._auth_headers()
        try:
            async with httpx.AsyncClient(headers=headers, timeout=self.TIMEOUT) as client:
                resp = await client.get(
                    f"{self.API_URL}/search/issues",
                    params={"q": f"repo:{owner}/{repo} type:pr state:open"},
                )
                resp.raise_for_status()
                return resp.json().get("total_count", -1)
        except (HTTPStatusError, ConnectTimeout, httpx.RequestError) as e:
            logger.warning(f"Failed to search PRs for {owner}/{repo} - {e}")
            return None

    async def get_org(self, owner: str, repo_data: Optional[dict] = None) -> dict:
        """Fetch organization metadata including verification status.

        Returns dict with: verified, org_url, description, topics, domains
        """

        if self.token is None:
            return {"verified": False, "org_url": None, "description": None, "topics": None, "domains": None}

        headers = self._auth_headers()
        try:
            async with httpx.AsyncClient(headers=headers, timeout=self.TIMEOUT) as client:
                if repo_data is None:
                    resp = await client.get(f"{self.API_URL}/repos/{owner}/{repo_data}")
                    resp.raise_for_status()
                    repo_data = resp.json()

                topics = repo_data.get("topics", [])
                domains = []
                homepage = repo_data.get("homepage")
                description = repo_data.get("description")
                if homepage:
                    domains.append(homepage)
                if description:
                    description = description.strip()

                owner_info = repo_data.get("owner", {})
                if owner_info.get("type") != "Organization":
                    return {
                        "verified": False,
                        "org_url": None,
                        "description": None,
                        "topics": None,
                        "domains": domains,
                    }

                org_login = owner_info.get("login")
                org_resp = await client.get(f"{self.API_URL}/orgs/{org_login}")
                org_resp.raise_for_status()
                org_data = org_resp.json()

                org_url = org_data.get("blog")
                if org_url:
                    domains.append(org_url)

                if not org_data.get("is_verified"):
                    return {
                        "verified": False,
                        "org_url": org_url,
                        "description": None,
                        "topics": None,
                        "domains": domains,
                    }
                return {
                    "verified": True,
                    "org_url": org_url,
                    "description": description,
                    "topics": topics,
                    "domains": domains,
                }
        except (HTTPStatusError, ConnectTimeout, httpx.RequestError) as e:
            logger.warning(f"Failed to fetch org details for {owner} - {e}")
            return {"verified": False, "org_url": None, "description": None, "topics": None, "domains": None}

    async def get_readme(self, owner: str, repo: str, path: Optional[str] = None) -> Optional[str]:
        """Fetch decoded README content. If path is given, looks for README in that subdirectory."""
        headers = self._auth_headers()
        url = f"{self.API_URL}/repos/{owner}/{repo}/readme"
        if path:
            url = f"{url}/{path}"
        try:
            async with httpx.AsyncClient(headers=headers, timeout=self.TIMEOUT) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
                content = data.get("content", "")
                if data.get("encoding") == "base64" and content:
                    return base64.b64decode(content).decode("utf-8", errors="replace")
                return content or None
        except (HTTPStatusError, ConnectTimeout, httpx.RequestError) as e:
            logger.warning(f"Failed to fetch README for {owner}/{repo} - {e}")
            return None

    async def get_ossf_score(self, owner: str, repo: str) -> Optional[float]:
        """Fetch OSSF Scorecard score."""

        headers = self.HEADERS.copy()
        headers["Accept"] = "application/json"
        try:
            async with httpx.AsyncClient(headers=headers, timeout=self.TIMEOUT) as client:
                resp = await client.get(f"{self.SCORECARD_URL}/{owner}/{repo}")
                resp.raise_for_status()
                return resp.json().get("score")
        except Exception as e:
            logger.warning(f"Failed to fetch OSSF score for {owner}/{repo} - {e}")
            return None

    @staticmethod
    def _next_url(link_header: Optional[str]) -> Optional[str]:
        if not link_header:
            return None
        for part in link_header.split(","):
            section = part.strip()
            if 'rel="next"' not in section:
                continue
            start, end = section.find("<"), section.find(">")
            if start == -1 or end <= start:
                return None
            return section[start + 1:end]
        return None

    async def get_security_advisories(self, owner: str, repo: str) -> Optional[list[dict]]:
        """Fetch all published security advisories for a GitHub repo, paginated."""
        headers = self._auth_headers()
        url: Optional[str] = f"{self.API_URL}/repos/{owner}/{repo}/security-advisories"
        params: Optional[dict] = {"per_page": 100}
        advisories: list[dict] = []
        try:
            async with httpx.AsyncClient(headers=headers, timeout=self.TIMEOUT, follow_redirects=True) as client:
                while url:
                    resp = await client.get(url, params=params)
                    resp.raise_for_status()
                    page = resp.json()
                    if not isinstance(page, list):
                        break
                    advisories.extend(page)
                    url = self._next_url(resp.headers.get("link"))
                    params = None
        except (HTTPStatusError, ConnectTimeout, httpx.RequestError) as e:
            logger.warning(f"Failed to fetch security advisories for {owner}/{repo} - {e}")
            return None
        return advisories

__all__ = ["GitHubClient"]

