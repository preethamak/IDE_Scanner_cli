from typing import Any


def strip_cache_noise(subject: Any) -> Any:
    """Cache key transform that replaces repo_path with commit_sha.

    This ensures extractors that auto-clone repos produce stable cache keys
    tied to the specific commit rather than a volatile temp directory path.
    Falls back to a boolean if no commit_sha is available.
    """
    if isinstance(subject, dict) and "repo_path" in subject:
        commit_sha = subject.get("commit_sha")
        return {**subject, "repo_path": commit_sha or (subject["repo_path"] is not None)}
    return subject

