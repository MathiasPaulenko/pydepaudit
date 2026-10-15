"""GitHub API client for upstream repository health."""

import os
import re
from datetime import datetime
from typing import Any

import httpx

from pydepaudit.models import RepoHealth

BASE_URL = "https://api.github.com"

_REPO_RE = re.compile(r"github\.com/([^/:\s]+)/([^/#?\s]+)")
_NON_REPO_OWNERS = {"sponsors", "topics", "marketplace", "collections", "features"}
_LAST_PAGE_RE = re.compile(r'[?&]page=(\d+)>;\s*rel="last"')


def find_repo(project_urls: dict[str, str]) -> str | None:
    """Extract an 'owner/name' GitHub repo from PyPI project_urls."""
    for url in project_urls.values():
        match = _REPO_RE.search(str(url))
        if match and match.group(1).lower() not in _NON_REPO_OWNERS:
            owner, name = match.groups()
            return f"{owner}/{name.removesuffix('.git')}"
    return None


class GitHubClient:
    """Fetch repository health signals from the GitHub API.

    Works unauthenticated (60 req/h); set GITHUB_TOKEN to raise the limit.
    """

    def __init__(
        self, client: httpx.Client | None = None, token: str | None = None
    ) -> None:
        self._client = client or _default_client(token)

    def repo_health(self, repo: str) -> RepoHealth | None:
        """Return health signals for 'owner/name', or None if unavailable."""
        response = self._client.get(f"/repos/{repo}")
        if response.status_code in (403, 404):
            return None
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        pushed_at = data.get("pushed_at")
        return RepoHealth(
            url=f"https://github.com/{repo}",
            archived=bool(data.get("archived", False)),
            pushed_at=datetime.fromisoformat(pushed_at) if pushed_at else None,
            open_issues=int(data.get("open_issues_count", 0)),
            contributors=self._contributors(repo),
        )

    def _contributors(self, repo: str) -> int | None:
        """Approximate contributor count via a 1-per-page paginated query."""
        response = self._client.get(
            f"/repos/{repo}/contributors",
            params={"per_page": "1", "anon": "true"},
        )
        if response.status_code != 200:
            return None
        match = _LAST_PAGE_RE.search(response.headers.get("Link", ""))
        if match:
            return int(match.group(1))
        return len(response.json())


def _default_client(token: str | None) -> httpx.Client:
    token = token or os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=BASE_URL, headers=headers, timeout=10.0)
