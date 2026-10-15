import httpx
import respx

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
def test_repo_health_unavailable() -> None:
    respx.get("https://api.github.com/repos/a/gone").mock(
        return_value=httpx.Response(404)
    )
    assert GitHubClient().repo_health("a/gone") is None
