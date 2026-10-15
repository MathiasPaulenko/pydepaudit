import httpx
import pytest
import respx

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
def test_package_http_error() -> None:
    respx.get("https://pypi.org/pypi/boom/json").mock(return_value=httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        PyPIClient().package("boom")
