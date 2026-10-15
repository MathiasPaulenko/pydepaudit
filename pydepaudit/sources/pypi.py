"""PyPI JSON API client."""

from datetime import datetime
from typing import Any

import httpx

from pydepaudit.models import PackageMetadata

BASE_URL = "https://pypi.org"


class PyPIClient:
    """Fetch package metadata from the PyPI JSON API."""

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(base_url=BASE_URL, timeout=10.0)

    def package(self, name: str) -> PackageMetadata | None:
        """Return metadata for *name*, or None if it does not exist on PyPI."""
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
    return text or None
