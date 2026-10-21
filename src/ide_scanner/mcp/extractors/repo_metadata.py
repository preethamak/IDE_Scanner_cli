"""RepoMetadataExtractor — fetches GitHub repo + org metadata."""

import asyncio
from typing import Any, Optional, Union

from pydantic import BaseModel

from ..base import BaseExtractor, DoNotCache
from .utils.github import GitHubClient


class RepoMetadataResult(BaseModel):
    """Aggregated repository and organization metadata."""

    repo_url: Optional[str] = None
    verified: Optional[bool] = None
    open_source: Optional[bool] = None
    stars: Optional[int] = None
    forks: Optional[int] = None
    open_issues: Optional[int] = None
    open_prs: Optional[int] = None
    latest_commit: Optional[dict] = None
    ossf_score: Optional[float] = None

    org_verified: Optional[bool] = None
    org_url: Optional[str] = None
    org_description: Optional[str] = None
    org_topics: Optional[list[str]] = None
    org_domains: Optional[list[str]] = None


class RepoMetadataExtractor(BaseExtractor):
    """Extracts repository details and org metadata from GitHub."""

    name = "repo_metadata"
    version = "1.0"

    def __init__(self, cache_service, *, gh_token=None, gh_tokens=None):
        super().__init__(cache_service)
        self._gh_client = GitHubClient(gh_token=gh_token, gh_tokens=gh_tokens)

    async def _compute(self, subject: Any, **kwargs) -> Union[RepoMetadataResult, DoNotCache[RepoMetadataResult]]:
        repo_url = subject.get("repo_url") if isinstance(subject, dict) else None
        if not repo_url:
            return RepoMetadataResult()

        owner, repo, full_ref = GitHubClient.parse_github_url(repo_url)
        if not owner or not repo:
            return RepoMetadataResult(repo_url=repo_url)

        gh = self._gh_client

        # Run all API calls concurrently
        repo_data_task = asyncio.create_task(gh.get_repo(owner, repo))
        latest_commit_task = asyncio.create_task(gh.get_latest_commit(owner, repo, full_ref))
        open_prs_task = asyncio.create_task(gh.search_prs(owner, repo))
        ossf_task = asyncio.create_task(gh.get_ossf_score(owner, repo))

        repo_data, latest_commit, open_prs, ossf_score = await asyncio.gather(
            repo_data_task, latest_commit_task, open_prs_task, ossf_task
        )

        if repo_data is None:
            return DoNotCache(
                RepoMetadataResult(repo_url=repo_url),
                reason=f"GitHub API failed for {owner}/{repo} — not caching degraded result",
            )

        stars = repo_data.get("stargazers_count", -1)
        forks = repo_data.get("forks_count", -1)
        open_issues = repo_data.get("open_issues_count", -1)

        # Fetch org details using the already-fetched repo data
        org_meta = await gh.get_org(owner, repo_data=repo_data)

        # Check org verification (also from repo details)
        owner_info = repo_data.get("owner", {})
        verified = False
        if owner_info.get("type") == "Organization":
            verified = org_meta.get("verified", False)

        return RepoMetadataResult(
            repo_url=repo_url,
            verified=verified,
            open_source=True,
            stars=stars,
            forks=forks,
            open_issues=open_issues,
            open_prs=open_prs,
            latest_commit=latest_commit,
            ossf_score=ossf_score,
            org_verified=org_meta.get("verified"),
            org_url=org_meta.get("org_url"),
            org_description=org_meta.get("description"),
            org_topics=org_meta.get("topics"),
            org_domains=org_meta.get("domains"),
        )


__all__ = [
    "RepoMetadataExtractor",
    "RepoMetadataResult",
]

