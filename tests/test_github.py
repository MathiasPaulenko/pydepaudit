from pathlib import Path

import httpx
import pytest
import respx

from pydepaudit.cache import FileCache
from pydepaudit.sources.github import GitHubClient, find_repo


def test_find_repo() -> None:
    urls = {"Source": "https://github.com/psf/requests"}
    assert find_repo(urls) == "psf/requests"


def test_find_repo_cleans_suffixes() -> None:
    assert find_repo({"Code": "https://github.com/a/b.git"}) == "a/b"
    assert find_repo({"Issues": "https://github.com/a/b/issues"}) == "a/b"
    assert find_repo({"Code": "https://github.com/a/.git"}) is None
    assert find_repo({"Code": "https://github.com/a/..git"}) is None


def test_find_repo_skips_non_repos() -> None:
    assert find_repo({"Funding": "https://github.com/sponsors/a"}) is None
    assert find_repo({"Homepage": "https://example.com"}) is None
    assert find_repo({}) is None
    assert find_repo(None) is None  # type: ignore[arg-type]
    assert find_repo({1: "https://github.com/a/b"}) is None  # type: ignore[dict-item]


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
                    '<https://api.github.com/r/c?page=150&per_page=1>; rel="last"'
                )
            },
        )
    )
    respx.get(
        "https://api.securityscorecards.dev/projects/github.com/psf/requests"
    ).mock(return_value=httpx.Response(200, json={"score": 8.4}))

    health = GitHubClient().repo_health("psf/requests")

    assert health is not None
    assert health.archived is False
    assert health.open_issues == 42
    assert health.contributors == 150
    assert health.scorecard == 8.4
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
    respx.get("https://api.securityscorecards.dev/projects/github.com/a/tiny").mock(
        return_value=httpx.Response(404)
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
    respx.get("https://api.securityscorecards.dev/projects/github.com/a/b").mock(
        return_value=httpx.Response(200, json={"score": "NaN"})
    )
    health = GitHubClient().repo_health("a/b")
    assert health is not None
    assert health.contributors == 42
    assert health.open_issues == 0
    assert health.scorecard is None  # non-numeric score degrades cleanly


@respx.mock
def test_client_with_token() -> None:
    repo_route = respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(
            200,
            json={"archived": False, "pushed_at": None, "open_issues_count": 0},
        )
    )
    respx.get("https://api.github.com/repos/a/b/contributors").mock(
        return_value=httpx.Response(200, json=[])
    )
    scorecard_route = respx.get(
        "https://api.securityscorecards.dev/projects/github.com/a/b"
    ).mock(return_value=httpx.Response(404))
    client = GitHubClient(token="tok")
    client.repo_health("a/b")
    # the GitHub token reaches api.github.com but never a third-party host
    assert repo_route.calls.last.request.headers["authorization"] == "Bearer tok"
    assert scorecard_route.calls.last.request.headers.get("authorization", "") == ""
    client.close()


@respx.mock
def test_github_redirect_never_follows_external_host() -> None:
    respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(
            302, headers={"Location": "https://internal.example/secret"}
        )
    )
    external = respx.get("https://internal.example/secret").mock(
        return_value=httpx.Response(
            200, json={"archived": False, "pushed_at": None, "open_issues_count": 0}
        )
    )
    client = GitHubClient(token="secret")
    with pytest.raises(httpx.HTTPStatusError):
        client._fetch("a/b")
    assert external.call_count == 0


@respx.mock
def test_repo_health_deep_json_is_clean_malformed_error() -> None:
    body = b'{"deep":' + b"[" * 20000 + b"0" + b"]" * 20000 + b"}"
    respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(200, content=body)
    )
    with pytest.raises(ValueError, match="malformed GitHub JSON"):
        GitHubClient().repo_health("a/b")


@respx.mock
def test_github_same_origin_rename_redirect_uses_new_repo(
    tmp_path: Path,
) -> None:
    respx.get("https://api.github.com/repos/a/old").mock(
        return_value=httpx.Response(301, headers={"Location": "/repos/a/new"})
    )
    route = respx.get("https://api.github.com/repos/a/new").mock(
        return_value=httpx.Response(
            200, json={"archived": False, "pushed_at": None, "open_issues_count": 0}
        )
    )
    respx.get("https://api.github.com/repos/a/new/contributors").mock(
        return_value=httpx.Response(200, json=[{"login": "owner"}])
    )
    respx.get("https://api.securityscorecards.dev/projects/github.com/a/new").mock(
        return_value=httpx.Response(404)
    )
    client = GitHubClient(cache=FileCache(tmp_path / "cache"))
    health = client.repo_health("a/old")
    cached = client.repo_health("a/old")
    assert health is not None and health.url == "https://github.com/a/new"
    assert cached == health
    assert route.call_count == 1


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
    respx.get("https://api.securityscorecards.dev/projects/github.com/a/b").mock(
        return_value=httpx.Response(200, json={"score": 6.2})
    )
    client = GitHubClient(cache=cache)
    first = client.repo_health("a/b")
    # second call must hit the cache — the routes are already satisfied
    second = client.repo_health("a/b")
    assert first == second
    assert second is not None and second.contributors == 2
    assert second.scorecard == 6.2


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
    respx.get("https://api.securityscorecards.dev/projects/github.com/a/b").mock(
        return_value=httpx.Response(404)
    )
    health = GitHubClient(cache=cache).repo_health("a/b")
    assert health is not None
    assert health.contributors is None  # contributors endpoint failed


@respx.mock
def test_repo_health_cache_without_found_flag_refetches(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache")
    cache.set("github:a/b", {})
    route = respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(
            200, json={"archived": False, "pushed_at": None, "open_issues_count": 0}
        )
    )
    respx.get("https://api.github.com/repos/a/b/contributors").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.get("https://api.securityscorecards.dev/projects/github.com/a/b").mock(
        return_value=httpx.Response(404)
    )
    assert GitHubClient(cache=cache).repo_health("a/b") is not None
    assert route.call_count == 1


@respx.mock
def test_repo_health_cache_url_must_match_key(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache")
    cache.set(
        "github:a/b",
        {
            "found": True,
            "url": "https://github.com/evil/repo",
            "archived": False,
            "pushed_at": None,
            "open_issues": 0,
            "contributors": None,
            "scorecard": None,
        },
    )
    route = respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(
            200, json={"archived": False, "pushed_at": None, "open_issues_count": 0}
        )
    )
    respx.get("https://api.github.com/repos/a/b/contributors").mock(
        return_value=httpx.Response(200, json=[])
    )
    respx.get("https://api.securityscorecards.dev/projects/github.com/a/b").mock(
        return_value=httpx.Response(404)
    )
    health = GitHubClient(cache=cache).repo_health("a/b")
    assert health is not None and health.url == "https://github.com/a/b"
    assert route.call_count == 1


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
    respx.get("https://api.securityscorecards.dev/projects/github.com/a/b").mock(
        return_value=httpx.Response(404)
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


@respx.mock
def test_repo_health_rate_limited_not_cached(tmp_path: Path) -> None:
    # a 403 (rate limit / abuse) is transient: don't poison the cache with it
    cache = FileCache(tmp_path / "cache")
    route = respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(403)
    )
    client = GitHubClient(cache=cache)
    assert client.repo_health("a/b") is None
    assert client.repo_health("a/b") is None
    assert route.call_count == 2  # each call retried — no negative cache


@respx.mock
def test_repo_health_aux_endpoint_outage() -> None:
    # scorecard service down (DNS/timeout) must not kill the audit
    respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(
            200,
            json={"archived": False, "pushed_at": None, "open_issues_count": 1},
        )
    )
    respx.get("https://api.github.com/repos/a/b/contributors").mock(
        side_effect=httpx.ConnectError("down")
    )
    respx.get("https://api.securityscorecards.dev/projects/github.com/a/b").mock(
        side_effect=httpx.ConnectError("down")
    )
    health = GitHubClient().repo_health("a/b")
    assert health is not None
    assert health.contributors is None
    assert health.scorecard is None


@respx.mock
def test_repo_health_corrupt_cache_wrong_types(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache")
    # scorecard as a string would crash the scorecard rule with TypeError
    cache.set("github:a/b", {"found": True, "url": "u", "scorecard": "high"})
    respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(
            200, json={"archived": False, "pushed_at": None, "open_issues_count": 0}
        )
    )
    respx.get("https://api.github.com/repos/a/b/contributors").mock(
        return_value=httpx.Response(403)
    )
    respx.get("https://api.securityscorecards.dev/projects/github.com/a/b").mock(
        return_value=httpx.Response(404)
    )
    health = GitHubClient(cache=cache).repo_health("a/b")
    assert health is not None and health.scorecard is None


def test_find_repo_rejects_dot_segments() -> None:
    assert find_repo({"Source": "https://github.com/../x"}) is None
    assert find_repo({"Source": "https://github.com/./b"}) is None


def test_repo_health_invalid_repo_string() -> None:
    # control chars would raise httpx.InvalidURL (not an HTTPError)
    assert GitHubClient().repo_health("a/b\x00") is None
    assert GitHubClient().repo_health("") is None
    assert GitHubClient().repo_health("a") is None
    assert GitHubClient().repo_health("../repo") is None
    assert GitHubClient().repo_health("owner/..") is None
    assert GitHubClient().repo_health(None) is None  # type: ignore[arg-type]


@respx.mock
def test_scorecard_rejects_non_finite_and_out_of_range_scores() -> None:
    route = respx.get(
        "https://api.securityscorecards.dev/projects/github.com/a/b"
    ).mock()
    client = GitHubClient()
    for raw in (
        b'{"score":NaN}',
        b'{"score":Infinity}',
        b'{"score":-1}',
        b'{"score":10.1}',
    ):
        route.return_value = httpx.Response(200, content=raw)
        assert client._scorecard("a/b") is None


@respx.mock
def test_scorecard_does_not_follow_external_redirect() -> None:
    respx.get("https://api.securityscorecards.dev/projects/github.com/a/b").mock(
        return_value=httpx.Response(
            302, headers={"Location": "https://internal.example/secret"}
        )
    )
    external = respx.get("https://internal.example/secret").mock(
        return_value=httpx.Response(200, json={"score": 10})
    )
    assert GitHubClient()._scorecard("a/b") is None
    assert external.call_count == 0


def test_find_repo_www_prefix() -> None:
    # www.github.com redirects to github.com — a legitimate repo URL
    assert find_repo({"Source": "https://www.github.com/a/b"}) == "a/b"
    # but a lookalike subdomain is still rejected
    assert find_repo({"Source": "https://wwwx.github.com/a/b"}) is None
