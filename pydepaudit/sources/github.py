"""GitHub API client for upstream repository health."""

import os
import re
from datetime import UTC, datetime
from math import isfinite
from typing import Any
from urllib.parse import urljoin

import httpx

from pydepaudit.cache import FileCache
from pydepaudit.models import RepoHealth

BASE_URL = "https://api.github.com"

# github.com must be the URL host — after a scheme, 'git@' or at string start.
# Subdomains (x.github.com) and lookalikes (evil.com?u=github.com/x) are not repos.
# GitHub owner/repo names are restricted to alphanumerics, '-', '_' and '.'
_REPO_CHARS = r"[A-Za-z0-9_.-]+"
_REPO_RE = re.compile(
    rf"(?:^|://|@)(?:www\.)?github\.com[/:]({_REPO_CHARS})/({_REPO_CHARS})"
)
_REPO_FULL_RE = re.compile(rf"{_REPO_CHARS}/{_REPO_CHARS}")
_NON_REPO_OWNERS = {"sponsors", "topics", "marketplace", "collections", "features"}
_LAST_PAGE_RE = re.compile(r'[?&]page=(\d+)(?:&[^>]*)?>;\s*rel="last"')

# project_urls keys checked first — they point at the repo more reliably than
# Homepage or Documentation links
_PREFERRED_KEYS = ("source", "repository", "source code", "code", "homepage")


def find_repo(project_urls: dict[str, str]) -> str | None:
    """Extract an 'owner/name' GitHub repo from PyPI project_urls."""
    if not isinstance(project_urls, dict):
        return None
    entries = [
        (key, url)
        for key, url in project_urls.items()
        if isinstance(key, str) and isinstance(url, str)
    ]
    ordered = sorted(
        entries,
        key=lambda kv: 0 if kv[0].lower() in _PREFERRED_KEYS else 1,
    )
    for _, url in ordered:
        match = _REPO_RE.search(str(url))
        if match and match.group(1).lower() not in _NON_REPO_OWNERS:
            owner = match.group(1)
            name = match.group(2).removesuffix(".git")
            if owner in (".", "..") or name in ("", ".", ".."):
                continue
            return f"{owner}/{name}"
    return None


class _TransientError(Exception):
    """A soft failure (e.g. rate limiting) that must not be cached."""


class GitHubClient:
    """Fetch repository health signals from the GitHub API.

    Works unauthenticated (60 req/h); set GITHUB_TOKEN to raise the limit.
    """

    def __init__(
        self,
        client: httpx.Client | None = None,
        token: str | None = None,
        cache: FileCache | None = None,
    ) -> None:
        if client is None:
            token = token or os.environ.get("GITHUB_TOKEN")
            client = _default_client()
        self._client = client
        # auth is applied per-request so the token can never leak to
        # third-party hosts hit through the same client (e.g. Scorecard)
        self._auth = {"Authorization": f"Bearer {token}"} if token else None
        self._cache = cache

    def close(self) -> None:
        """Release the underlying HTTP client resources."""
        self._client.close()

    def repo_health(self, repo: str) -> RepoHealth | None:
        """Return health signals for 'owner/name', or None if unavailable."""
        if not isinstance(repo, str) or not _REPO_FULL_RE.fullmatch(repo):
            return None
        owner, name = repo.split("/", 1)
        if owner in (".", "..") or name in (".", ".."):
            return None  # invalid repo string can't be fetched anyway
        key = f"github:{repo.lower()}"
        if self._cache is not None and (cached := self._cache.get(key)) is not None:
            try:
                health = _from_cached(cached)
                requested_repo = cached.get("requested_repo")
                if not isinstance(requested_repo, str) or (
                    requested_repo.casefold() != repo.casefold()
                ):
                    raise ValueError("cached repository does not match its key")
                return health
            except (TypeError, ValueError, KeyError):
                pass  # stale schema — refetch
        try:
            health = self._fetch(repo)
        except _TransientError:
            # rate-limited or blocked — don't cache a transient miss as "gone"
            return None
        if self._cache is not None:
            self._cache.set(key, _to_cached(health, repo))
        return health

    def _fetch(self, repo: str) -> RepoHealth | None:
        response = self._get_github(f"/repos/{repo}")
        if response.status_code == 404:
            return None
        if response.status_code == 403:
            raise _TransientError(repo)
        response.raise_for_status()
        try:
            data: Any = response.json()
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"malformed GitHub JSON for {repo!r}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"malformed GitHub response for {repo!r}")
        redirected_repo = response.url.path.removeprefix("/repos/")
        if _REPO_FULL_RE.fullmatch(redirected_repo):
            repo = redirected_repo
        pushed_at = data.get("pushed_at")
        open_issues = data.get("open_issues_count")
        archived = data.get("archived")
        return RepoHealth(
            url=f"https://github.com/{repo}",
            archived=archived if isinstance(archived, bool) else False,
            pushed_at=_parse_timestamp(pushed_at),
            open_issues=(
                open_issues if type(open_issues) is int and open_issues >= 0 else 0
            ),
            contributors=self._contributors(repo),
            scorecard=self._scorecard(repo),
        )

    def _contributors(self, repo: str) -> int | None:
        """Approximate contributor count via a 1-per-page paginated query."""
        try:
            response = self._get_github(
                f"/repos/{repo}/contributors",
                params={"per_page": "1", "anon": "true"},
            )
            if response.status_code != 200:
                return None
            match = _LAST_PAGE_RE.search(response.headers.get("Link", ""))
            if match:
                return int(match.group(1))
            payload = response.json()
        except (httpx.HTTPError, ValueError, RecursionError):
            return None  # auxiliary signal — best effort
        return len(payload) if isinstance(payload, list) else None

    def _scorecard(self, repo: str) -> float | None:
        """OpenSSF Scorecard aggregate score (0-10), None when unrated."""
        try:
            response = self._client.get(
                f"https://api.securityscorecards.dev/projects/github.com/{repo}",
                # blank out any client-level auth so a GitHub token never
                # reaches a third-party host
                headers={"Authorization": ""},
                follow_redirects=False,
            )
            if response.status_code != 200:
                return None
            score = response.json().get("score")
        except (httpx.HTTPError, ValueError, RecursionError, AttributeError):
            return None  # third-party service outage must not kill the audit
        if (
            isinstance(score, bool)
            or not isinstance(score, int | float)
            or not 0 <= score <= 10
            or not isfinite(score)
        ):
            return None
        return float(score)

    def _get_github(
        self, path: str, params: dict[str, str] | None = None
    ) -> httpx.Response:
        """Follow only same-origin repository redirects, never arbitrary hosts."""
        response = self._client.get(
            path,
            params=params,
            headers=self._auth,
            follow_redirects=False,
        )
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            if location:
                try:
                    target = httpx.URL(urljoin(str(response.url), location))
                except (ValueError, httpx.InvalidURL):
                    return response
                if (
                    target.scheme == "https"
                    and target.host == "api.github.com"
                    and target.port is None
                    and not target.username
                    and not target.password
                    and not target.query
                    and _REPO_FULL_RE.fullmatch(target.path.removeprefix("/repos/"))
                ):
                    response = self._client.get(
                        target, headers=self._auth, follow_redirects=False
                    )
        return response


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO 8601 timestamp; malformed values degrade to None."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _to_cached(health: RepoHealth | None, requested_repo: str) -> dict[str, Any]:
    if health is None:
        return {"found": False, "requested_repo": requested_repo}
    return {
        "found": True,
        "requested_repo": requested_repo,
        "url": health.url,
        "archived": health.archived,
        "pushed_at": health.pushed_at.isoformat() if health.pushed_at else None,
        "open_issues": health.open_issues,
        "contributors": health.contributors,
        "scorecard": health.scorecard,
    }


def _from_cached(data: Any) -> RepoHealth | None:
    if not isinstance(data, dict):
        raise ValueError("malformed cached repo health")
    found = data.get("found")
    if not isinstance(found, bool):
        raise ValueError("malformed cached repo health")
    if not found:
        return None
    url = data["url"]
    url_repo = url.removeprefix("https://github.com/") if isinstance(url, str) else ""
    pushed_at = data.get("pushed_at")
    open_issues = data.get("open_issues", 0)
    contributors = data.get("contributors")
    scorecard = data.get("scorecard")
    archived = data.get("archived", False)
    parsed_pushed_at = _parse_timestamp(pushed_at)
    if (
        not isinstance(url, str)
        or not _REPO_FULL_RE.fullmatch(url_repo)
        or not isinstance(archived, bool)
        or (pushed_at is not None and not isinstance(pushed_at, str))
        or not isinstance(open_issues, int)
        or isinstance(open_issues, bool)
        or open_issues < 0
        or (contributors is not None and not isinstance(contributors, int))
        or isinstance(contributors, bool)
        or (contributors is not None and contributors < 0)
        or (
            scorecard is not None
            and (
                isinstance(scorecard, bool)
                or not isinstance(scorecard, int | float)
                or not 0 <= scorecard <= 10
                or not isfinite(scorecard)
            )
        )
    ):
        raise ValueError("malformed cached repo health")
    if pushed_at and parsed_pushed_at is None:
        raise ValueError("malformed cached repo timestamp")
    return RepoHealth(
        url=url,
        archived=archived,
        pushed_at=parsed_pushed_at,
        open_issues=open_issues,
        contributors=contributors,
        scorecard=scorecard,
    )


def _default_client() -> httpx.Client:
    return httpx.Client(
        base_url=BASE_URL,
        headers={"Accept": "application/vnd.github+json"},
        timeout=10.0,
        follow_redirects=False,
    )
