"""PyPI JSON API client."""

from datetime import datetime
from typing import Any

import httpx

from pydepaudit.cache import FileCache
from pydepaudit.models import PackageMetadata

BASE_URL = "https://pypi.org"


class PyPIClient:
    """Fetch package metadata from the PyPI JSON API."""

    def __init__(
        self,
        client: httpx.Client | None = None,
        cache: FileCache | None = None,
    ) -> None:
        self._client = client or httpx.Client(base_url=BASE_URL, timeout=10.0)
        self._cache = cache

    def close(self) -> None:
        """Release the underlying HTTP client resources."""
        self._client.close()

    def package(self, name: str) -> PackageMetadata | None:
        """Return metadata for *name*, or None if it does not exist on PyPI."""
        key = f"pypi:{name.lower()}"
        if self._cache is not None and (cached := self._cache.get(key)) is not None:
            return _from_cached(cached)
        meta = self._fetch(name)
        if self._cache is not None:
            self._cache.set(key, _to_cached(meta))
        return meta

    def _fetch(self, name: str) -> PackageMetadata | None:
        response = self._client.get(f"/pypi/{name}/json")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        info = data["info"]

        latest = info.get("version", "")
        files = data.get("releases", {}).get(latest, [])
        timestamps = [
            datetime.fromisoformat(f["upload_time_iso_8601"])
            for f in files
            if f.get("upload_time_iso_8601")
        ]

        return PackageMetadata(
            name=info.get("name", name),
            latest_version=latest,
            license=_license(info),
            last_release=max(timestamps) if timestamps else None,
            project_urls=info.get("project_urls") or {},
        )


def _to_cached(meta: PackageMetadata | None) -> dict[str, Any]:
    if meta is None:
        return {"found": False}
    return {
        "found": True,
        "name": meta.name,
        "latest_version": meta.latest_version,
        "license": meta.license,
        "last_release": meta.last_release.isoformat() if meta.last_release else None,
        "project_urls": meta.project_urls,
    }


def _from_cached(data: dict[str, Any]) -> PackageMetadata | None:
    if not data.get("found"):
        return None
    last_release = data.get("last_release")
    return PackageMetadata(
        name=data["name"],
        latest_version=data["latest_version"],
        license=data.get("license"),
        last_release=datetime.fromisoformat(last_release) if last_release else None,
        project_urls=data.get("project_urls") or {},
    )


def _license(info: dict[str, Any]) -> str | None:
    """Best-effort license string from PyPI metadata.

    license_expression (PEP 639) is the most reliable; classifiers come next
    and the free-text license field last.
    """
    if expression := info.get("license_expression"):
        return str(expression)
    for classifier in info.get("classifiers", []):
        if classifier.startswith("License ::"):
            return str(classifier).rsplit("::", 1)[-1].strip()
    text = (info.get("license") or "").strip()
    # the free-text field sometimes holds an entire license text blob
    if not text or len(text) > 60 or "\n" in text:
        return None
    return text
