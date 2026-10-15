from pathlib import Path

import httpx
import respx

from pydepaudit.cache import FileCache
from pydepaudit.sources.github import GitHubClient, find_repo


def test_find_repo() -> None:
    urls = {"Source": "https://github.com/psf/requests"}
    assert find_repo(urls) == "psf/requests"


def test_find_repo_cleans_suffixes() -> None:
    assert find_repo({"Code": "https://github.com/a/b.git"}) == "a/b"
    assert find_repo({"Issues": "https://github.com/a/b/issues"}) == "a/b"


def test_find_repo_skips_non_repos() -> None:
    assert find_repo({"Funding": "https://github.com/sponsors/a"}) is None
    assert find_repo({"Homepage": "https://example.com"}) is None
    assert find_repo({}) is None


def test_find_repo_rejects_lookalike_hosts() -> None:
    assert find_repo({"Docs": "https://x.github.com/a/b"}) is None
    assert find_repo({"Homepage": "https://evil.com/?u=github.com/a/b"}) is None
    assert find_repo({"Source": "git@github.com:a/b.git"}) == "a/b"


def test_find_repo_prefers_source_key() -> None:
    urls = {
        "Tracker": "https://github.com/a/tracker-repo",
        "Source": "https://github.com/a/source-repo",
    }
    assert find_repo(urls) == "a/source-repo"


@respx.mock
def test_repo_health() -> None:
    respx.get("https://api.github.com/repos/psf/requests").mock(
        return_value=httpx.Response(
            200,
            json={
                "archived": False,
                "pushed_at": "2025-10-01T12:00:00Z",
                "open_issues_count": 42,
            },
        )
    )
    respx.get("https://api.github.com/repos/psf/requests/contributors").mock(
        return_value=httpx.Response(
            200,
            json=[{"login": "a"}],
            headers={
                "Link": (
                    '<https://api.github.com/r/c?page=2>; rel="next", '
                    '<https://api.github.com/r/c?page=150>; rel="last"'
                )
            },
        )
    )

    health = GitHubClient().repo_health("psf/requests")

    assert health is not None
    assert health.archived is False
    assert health.open_issues == 42
    assert health.contributors == 150
    assert health.pushed_at is not None
    assert health.pushed_at.year == 2025


@respx.mock
def test_repo_health_single_contributor() -> None:
    respx.get("https://api.github.com/repos/a/tiny").mock(
        return_value=httpx.Response(
            200,
            json={"archived": False, "pushed_at": None, "open_issues_count": 0},
        )
    )
    respx.get("https://api.github.com/repos/a/tiny/contributors").mock(
        return_value=httpx.Response(200, json=[{"login": "a"}])
    )
    health = GitHubClient().repo_health("a/tiny")
    assert health is not None
    assert health.contributors == 1


@respx.mock
def test_repo_health_paginated_contributors() -> None:
    respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(
            200,
            json={
                "archived": False,
                "pushed_at": "2024-06-01T00:00:00Z",
                "open_issues_count": None,  # malformed
            },
        )
    )
    respx.get("https://api.github.com/repos/a/b/contributors").mock(
        return_value=httpx.Response(
            200,
            json=[{"login": "x"}],
            headers={
                "Link": '<https://api.github.com/x?per_page=1&page=42>; rel="last"'
            },
        )
    )
    health = GitHubClient().repo_health("a/b")
    assert health is not None
    assert health.contributors == 42
    assert health.open_issues == 0


def test_client_with_token() -> None:
    client = GitHubClient(token="tok")
    assert client._client.headers["Authorization"] == "Bearer tok"
    client.close()


@respx.mock
def test_repo_health_cache_roundtrip(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache")
    respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(
            200,
            json={
                "archived": True,
                "pushed_at": "2024-06-01T00:00:00Z",
                "open_issues_count": 5,
            },
        )
    )
    respx.get("https://api.github.com/repos/a/b/contributors").mock(
        return_value=httpx.Response(200, json=[{"login": "x"}, {"login": "y"}])
    )
    client = GitHubClient(cache=cache)
    first = client.repo_health("a/b")
    # second call must hit the cache — the routes are already satisfied
    second = client.repo_health("a/b")
    assert first == second
    assert second is not None and second.contributors == 2


@respx.mock
def test_repo_health_cache_negative(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache")
    route = respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(404)
    )
    client = GitHubClient(cache=cache)
    assert client.repo_health("a/b") is None
    assert client.repo_health("a/b") is None  # cached miss — no second request
    assert route.call_count == 1


@respx.mock
def test_repo_health_corrupt_cache_refetches(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache")
    cache.set("github:a/b", {"found": True})  # missing url → KeyError → refetch
    respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(
            200, json={"archived": False, "pushed_at": None, "open_issues_count": 0}
        )
    )
    respx.get("https://api.github.com/repos/a/b/contributors").mock(
        return_value=httpx.Response(403)
    )
    health = GitHubClient(cache=cache).repo_health("a/b")
    assert health is not None
    assert health.contributors is None  # contributors endpoint failed


@respx.mock
def test_repo_health_malformed_pushed_at() -> None:
    respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(
            200,
            json={"archived": False, "pushed_at": 12345, "open_issues_count": 0},
        )
    )
    respx.get("https://api.github.com/repos/a/b/contributors").mock(
        return_value=httpx.Response(200, json=[{"login": "x"}])
    )
    health = GitHubClient().repo_health("a/b")
    assert health is not None
    assert health.pushed_at is None


@respx.mock
def test_repo_health_unavailable() -> None:
    respx.get("https://api.github.com/repos/a/gone").mock(
        return_value=httpx.Response(404)
    )
    assert GitHubClient().repo_health("a/gone") is None
