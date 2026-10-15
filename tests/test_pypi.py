from pathlib import Path

import httpx
import pytest
import respx

from pydepaudit.cache import FileCache
from pydepaudit.sources.pypi import PyPIClient

REQUESTS_JSON = {
    "info": {
        "name": "requests",
        "version": "2.32.3",
        "license_expression": "Apache-2.0",
        "classifiers": ["License :: OSI Approved :: Apache Software License"],
        "project_urls": {"Homepage": "https://requests.readthedocs.io"},
    },
    "releases": {
        "2.32.3": [
            {"upload_time_iso_8601": "2024-05-29T15:37:47.140653Z"},
            {"upload_time_iso_8601": "2024-05-29T15:37:50.012345Z"},
        ]
    },
}


@respx.mock
def test_package() -> None:
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    meta = PyPIClient().package("requests")

    assert meta is not None
    assert meta.name == "requests"
    assert meta.latest_version == "2.32.3"
    assert meta.license == "Apache-2.0"
    assert meta.last_release is not None
    assert meta.last_release.isoformat() == "2024-05-29T15:37:50.012345+00:00"
    assert meta.project_urls == {"Homepage": "https://requests.readthedocs.io"}


@respx.mock
def test_package_license_fallback_to_classifier() -> None:
    payload = {
        "info": {
            "name": "oldlib",
            "version": "1.0",
            "license": "MIT licence text blob...",
            "classifiers": ["License :: OSI Approved :: MIT License"],
        },
        "releases": {"1.0": []},
    }
    respx.get("https://pypi.org/pypi/oldlib/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    meta = PyPIClient().package("oldlib")
    assert meta is not None
    assert meta.license == "MIT License"


@respx.mock
def test_package_license_blob_ignored() -> None:
    blob = "MIT License\n\nPermission is hereby granted..." * 10
    payload = {
        "info": {"name": "bloblib", "version": "1.0", "license": blob},
        "releases": {"1.0": []},
    }
    respx.get("https://pypi.org/pypi/bloblib/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    meta = PyPIClient().package("bloblib")
    assert meta is not None
    assert meta.license is None


@respx.mock
def test_package_not_found() -> None:
    respx.get("https://pypi.org/pypi/nonexistent/json").mock(
        return_value=httpx.Response(404)
    )
    assert PyPIClient().package("nonexistent") is None


@respx.mock
def test_package_malformed_payload() -> None:
    payload = {
        "info": {
            "name": "weird",
            "version": "1.0",
            "classifiers": [None, 42, "License :: OSI Approved :: MIT License"],
            "project_urls": ["not", "a", "dict"],
        },
        "releases": None,
    }
    respx.get("https://pypi.org/pypi/weird/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    meta = PyPIClient().package("weird")
    assert meta is not None
    assert meta.license == "MIT License"
    assert meta.project_urls == {}
    assert meta.last_release is None


@respx.mock
def test_corrupt_cache_falls_back_to_fetch(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache")
    cache.set("pypi:requests", {"found": True, "name": 123, "last_release": 5})
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    meta = PyPIClient(cache=cache).package("requests")
    assert meta is not None
    assert meta.name == "requests"


@respx.mock
def test_package_yanked_versions() -> None:
    payload = {
        "info": {"name": "t", "version": "2.0"},
        "releases": {
            "1.0": [{"yanked": True}, {"yanked": True}],
            "2.0": [{"yanked": False}],
            "3.0": [{"yanked": True}, {"yanked": False}],  # partial → not yanked
            "4.0": [{"yanked": "false"}],  # malformed truthy value is not boolean true
        },
    }
    respx.get("https://pypi.org/pypi/t/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    meta = PyPIClient().package("t")
    assert meta is not None and meta.yanked_versions == ("1.0",)


@respx.mock
def test_package_free_text_license() -> None:
    payload = {
        "info": {"name": "t", "version": "1.0", "license": "BSD-3-Clause"},
        "releases": {"1.0": []},
    }
    respx.get("https://pypi.org/pypi/t/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    meta = PyPIClient().package("t")
    assert meta is not None and meta.license == "BSD-3-Clause"


@respx.mock
def test_package_non_string_version() -> None:
    payload = {"info": {"name": "n", "version": [1, 0]}, "releases": {}}
    respx.get("https://pypi.org/pypi/n/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    meta = PyPIClient().package("n")
    assert meta is not None and meta.latest_version == ""


@respx.mock
def test_package_http_error() -> None:
    respx.get("https://pypi.org/pypi/boom/json").mock(return_value=httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        PyPIClient().package("boom")


@respx.mock
def test_package_does_not_follow_external_redirect() -> None:
    respx.get("https://pypi.org/pypi/pkg/json").mock(
        return_value=httpx.Response(
            302, headers={"Location": "https://internal.example/metadata"}
        )
    )
    external = respx.get("https://internal.example/metadata").mock(
        return_value=httpx.Response(200, json={"info": {}})
    )
    with pytest.raises(httpx.HTTPStatusError):
        PyPIClient().package("pkg")
    assert external.call_count == 0


@respx.mock
def test_package_deep_json_is_a_clean_malformed_response() -> None:
    body = b'{"info":' + b"[" * 20000 + b"0" + b"]" * 20000 + b"}"
    respx.get("https://pypi.org/pypi/pkg/json").mock(
        return_value=httpx.Response(200, content=body)
    )
    # rejected either at decode (RecursionError) or shape validation
    with pytest.raises(ValueError, match="malformed"):
        PyPIClient().package("pkg")


@respx.mock
def test_package_missing_info_is_an_error() -> None:
    # a 200 without an "info" object is malformed, not a real package
    respx.get("https://pypi.org/pypi/x/json").mock(
        return_value=httpx.Response(200, json={"releases": {}})
    )
    with pytest.raises(ValueError, match="malformed"):
        PyPIClient().package("x")


@pytest.mark.parametrize(
    "info",
    [
        {"name": "x", "version": ""},
        {"name": "x", "version": "not a version"},
        {"name": "different", "version": "1.0"},
    ],
)
@respx.mock
def test_package_rejects_malformed_or_mismatched_metadata(info: dict[str, str]) -> None:
    respx.get("https://pypi.org/pypi/x/json").mock(
        return_value=httpx.Response(200, json={"info": info, "releases": {}})
    )
    with pytest.raises(ValueError):
        PyPIClient().package("x")


@respx.mock
def test_package_bad_timestamp_skipped() -> None:
    payload = {
        "info": {"name": "t", "version": "1.0"},
        "releases": {
            "1.0": [
                {"upload_time_iso_8601": "not-a-date"},
                {"upload_time_iso_8601": "2024-01-01T00:00:00Z"},
            ]
        },
    }
    respx.get("https://pypi.org/pypi/t/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    meta = PyPIClient().package("t")
    assert meta is not None
    assert meta.last_release is not None
    assert meta.last_release.year == 2024


@respx.mock
def test_package_mixed_naive_and_aware_timestamps() -> None:
    payload = {
        "info": {"name": "t", "version": "1.0"},
        "releases": {
            "1.0": [
                {"upload_time_iso_8601": "2024-01-01T00:00:00"},
                {"upload_time_iso_8601": "2024-01-02T00:00:00Z"},
            ]
        },
    }
    respx.get("https://pypi.org/pypi/t/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    meta = PyPIClient().package("t")
    assert meta is not None and meta.last_release is not None
    assert meta.last_release.day == 2
    assert meta.last_release.tzinfo is not None


@respx.mock
def test_package_non_string_license_field() -> None:
    payload = {
        "info": {"name": "t", "version": "1.0", "license": 42},
        "releases": {"1.0": []},
    }
    respx.get("https://pypi.org/pypi/t/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    meta = PyPIClient().package("t")
    assert meta is not None and meta.license is None


@respx.mock
def test_package_filters_malformed_project_urls() -> None:
    payload = {
        "info": {
            "name": "t",
            "version": "1.0",
            "project_urls": {"Source": "https://github.com/a/b", "Docs": 4},
        },
        "releases": {},
    }
    respx.get("https://pypi.org/pypi/t/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    meta = PyPIClient().package("t")
    assert meta is not None
    assert meta.project_urls == {"Source": "https://github.com/a/b"}


@respx.mock
def test_cache_non_dict_refetches(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache")
    cache.set("pypi:requests", [1, 2, 3])  # valid JSON, wrong shape
    route = respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    meta = PyPIClient(cache=cache).package("requests")
    assert route.call_count == 1
    assert meta is not None and meta.name == "requests"


@respx.mock
def test_cache_dict_without_found_flag_refetches(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache")
    cache.set("pypi:requests", {})
    route = respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    meta = PyPIClient(cache=cache).package("requests")
    assert route.call_count == 1
    assert meta is not None and meta.name == "requests"


@respx.mock
def test_cache_metadata_name_must_match_key(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache")
    cache.set(
        "pypi:requests",
        {
            "found": True,
            "name": "evil-package",
            "latest_version": "1.0",
            "license": "MIT",
            "last_release": None,
            "project_urls": {},
            "yanked_versions": [],
        },
    )
    route = respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    meta = PyPIClient(cache=cache).package("requests")
    assert route.call_count == 1
    assert meta is not None and meta.name == "requests"


@respx.mock
def test_license_unknown_literal_is_none() -> None:
    respx.get("https://pypi.org/pypi/pkg/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {"name": "pkg", "version": "1.0", "license": "UNKNOWN"},
                "releases": {},
            },
        )
    )
    assert PyPIClient().package("pkg").license is None


@respx.mock
def test_license_expression_unknown_literal_is_none() -> None:
    respx.get("https://pypi.org/pypi/pkg/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {
                    "name": "pkg",
                    "version": "1.0",
                    "license_expression": "UNKNOWN",
                    "license": "UNKNOWN",
                },
                "releases": {},
            },
        )
    )
    assert PyPIClient().package("pkg").license is None


@respx.mock
def test_package_invalid_names_return_none() -> None:
    # control chars / slashes would raise httpx.InvalidURL — not a real package
    for name in ["", "\x00", "a b", "x/y/z", "../etc", ".hidden", "trail."]:
        assert PyPIClient().package(name) is None
    assert PyPIClient().package(None) is None  # type: ignore[arg-type]


@respx.mock
def test_package_canonicalizes_name(tmp_path: Path) -> None:
    # "Foo_Bar" and "foo-bar" are the same package — one cache entry, one URL
    cache = FileCache(tmp_path / "cache")
    payload = {
        **REQUESTS_JSON,
        "info": {**REQUESTS_JSON["info"], "name": "Foo_Bar"},
    }
    route = respx.get("https://pypi.org/pypi/foo-bar/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    assert PyPIClient(cache=cache).package("Foo_Bar") is not None
    assert PyPIClient(cache=cache).package("foo-bar") is not None
    assert route.call_count == 1
