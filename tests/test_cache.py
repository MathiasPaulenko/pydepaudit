import os
import sys
from pathlib import Path

import httpx
import pytest
import respx

from pydepaudit.cache import FileCache, default_cache_dir
from pydepaudit.sources.pypi import PyPIClient


def test_roundtrip(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    cache.set("pypi:requests", {"found": True, "name": "requests"})
    assert cache.get("pypi:requests") == {"found": True, "name": "requests"}


def test_default_cache_dir_uses_user_cache_root(tmp_path: Path, monkeypatch) -> None:
    if os.name == "nt":
        root_var = "LOCALAPPDATA"
    elif sys.platform != "darwin":
        root_var = "XDG_CACHE_HOME"
    else:
        monkeypatch.setenv("HOME", str(tmp_path))
        assert default_cache_dir() == tmp_path / "Library/Caches/pydepaudit"
        return
    root = tmp_path / "user-cache"
    monkeypatch.setenv(root_var, str(root))
    assert default_cache_dir() == root / "pydepaudit"


def test_miss(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    assert cache.get("nope") is None


def test_set_unserializable_is_swallowed(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    cache.set("k", object())  # not JSON-serializable → must not raise
    assert cache.get("k") is None


def test_set_nonstandard_json_numbers_is_swallowed(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    cache.set("k", {"score": float("nan")})
    assert cache.get("k") is None


def test_set_deeply_nested_value_is_best_effort(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    value: object = None
    for _ in range(20000):
        value = [value]
    cache.set("k", value)
    # deep nesting is dropped on RecursionError but round-trips fine on
    # Pythons whose json parser handles it — either way nothing must escape
    result = cache.get("k")
    assert result is None or isinstance(result, list)


def test_expired(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c", ttl_seconds=-1)
    cache.set("k", {"v": 1})
    assert cache.get("k") is None


def test_corrupt_file(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    cache.set("k", {"v": 1})
    cache._file("k").write_text("not json")
    assert cache.get("k") is None


def test_invalid_utf8_file_is_cache_miss(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    cache.set("k", {"v": 1})
    cache._file("k").write_bytes(b"\xff\xfe")
    assert cache.get("k") is None


def test_deeply_nested_json_is_handled_gracefully(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    cache._dir.mkdir()
    cache._file("k").write_text("[" * 20000 + "0" + "]" * 20000)
    result = cache.get("k")
    assert result is None or isinstance(result, list)


def test_invalid_ttl_rejected(tmp_path: Path) -> None:
    import math

    for ttl in (True, math.nan, math.inf, "1", 10**1000):
        with pytest.raises(ValueError, match="ttl_seconds"):
            FileCache(tmp_path, ttl)  # type: ignore[arg-type]


def test_key_sanitized(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    cache.set("github:psf/requests", {"found": True})
    assert len(list((tmp_path / "c").glob("github_psf_requests-*.json"))) == 1


def test_sanitized_key_collisions_remain_distinct(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    cache.set("github:a_b/c", {"repo": 1})
    cache.set("github:a/b_c", {"repo": 2})
    assert cache.get("github:a_b/c") == {"repo": 1}
    assert cache.get("github:a/b_c") == {"repo": 2}


def test_non_string_keys_are_best_effort(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    assert cache.get(None) is None  # type: ignore[arg-type]
    cache.set(None, {"v": 1})  # type: ignore[arg-type]


def test_surrogate_key_does_not_crash(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "c")
    key = "unpaired-\ud800"
    cache.set(key, {"v": 1})
    assert cache.get(key) == {"v": 1}


def test_concurrent_writes_never_torn(tmp_path: Path) -> None:
    # write-then-rename: readers must never observe a partial file
    import threading

    cache = FileCache(tmp_path / "c")
    errors: list[str] = []

    def writer(i: int) -> None:
        for n in range(50):
            cache.set("k", {"i": i, "n": n})

    def reader() -> None:
        for _ in range(200):
            v = cache.get("k")
            if v is not None and not (isinstance(v, dict) and "i" in v):
                errors.append(f"torn read: {v!r}")

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    threads.append(threading.Thread(target=reader))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


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
