from pathlib import Path

import httpx
import respx

from pydepaudit.cache import FileCache
from pydepaudit.sources.pypi import PyPIClient


def test_roundtrip(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    cache.set("pypi:requests", {"found": True, "name": "requests"})
    assert cache.get("pypi:requests") == {"found": True, "name": "requests"}


def test_miss(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    assert cache.get("nope") is None


def test_expired(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c", ttl_seconds=-1)
    cache.set("k", {"v": 1})
    assert cache.get("k") is None


def test_corrupt_file(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    cache.set("k", {"v": 1})
    (tmp_path / "c" / "k.json").write_text("not json")
    assert cache.get("k") is None


def test_key_sanitized(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    cache.set("github:psf/requests", {"found": True})
    assert (tmp_path / "c" / "github_psf_requests.json").is_file()


@respx.mock
def test_pypi_client_uses_cache(tmp_path: Path) -> None:
    route = respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {
                    "name": "requests",
                    "version": "2.32.3",
                    "license_expression": "Apache-2.0",
                    "classifiers": [],
                    "project_urls": {},
                },
                "releases": {"2.32.3": []},
            },
        )
    )
    cache = FileCache(tmp_path / "cache")

    first = PyPIClient(cache=cache).package("requests")
    second = PyPIClient(cache=cache).package("requests")

    assert route.call_count == 1
    assert first is not None and second is not None
    assert second.name == "requests"
    assert second.license == "Apache-2.0"


@respx.mock
def test_pypi_client_caches_not_found(tmp_path: Path) -> None:
    route = respx.get("https://pypi.org/pypi/ghost/json").mock(
        return_value=httpx.Response(404)
    )
    cache = FileCache(tmp_path / "cache")

    assert PyPIClient(cache=cache).package("ghost") is None
    assert PyPIClient(cache=cache).package("ghost") is None
    assert route.call_count == 1
