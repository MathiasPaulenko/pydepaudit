"""PyPI JSON API client."""

import re
from datetime import UTC, datetime
from typing import Any

import httpx
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pydepaudit.cache import FileCache
from pydepaudit.models import PackageMetadata

BASE_URL = "https://pypi.org"
_UNKNOWN_LICENSES = {"UNKNOWN", "NONE", "NOASSERTION"}

# PEP 508 name — anything else can't exist on PyPI and would produce an
# invalid request URL
_VALID_NAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$")


class PyPIClient:
    """Fetch package metadata from the PyPI JSON API."""

    def __init__(
        self,
        client: httpx.Client | None = None,
        cache: FileCache | None = None,
    ) -> None:
        self._client = client or httpx.Client(
            base_url=BASE_URL, timeout=10.0, follow_redirects=False
        )
        self._cache = cache

    def close(self) -> None:
        """Release the underlying HTTP client resources."""
        self._client.close()

    def package(self, name: str) -> PackageMetadata | None:
        """Return metadata for *name*, or None if it does not exist on PyPI."""
        if not isinstance(name, str):
            return None
        canonical = str(canonicalize_name(name))
        if not _VALID_NAME_RE.match(canonical):
            return None
        key = f"pypi:{canonical}"
        if self._cache is not None and (cached := self._cache.get(key)) is not None:
            try:
                metadata = _from_cached(cached)
                if (
                    metadata is not None
                    and str(canonicalize_name(metadata.name)) != canonical
                ):
                    raise ValueError("cached PyPI name does not match its key")
                return metadata
            except (TypeError, ValueError, KeyError):
                pass  # stale schema — refetch
        meta = self._fetch(canonical)
        if self._cache is not None:
            self._cache.set(key, _to_cached(meta))
        return meta

    def _fetch(self, name: str) -> PackageMetadata | None:
        response = self._client.get(f"/pypi/{name}/json", follow_redirects=False)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        try:
            data: Any = response.json()
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"malformed PyPI JSON for {name!r}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("info"), dict):
            raise ValueError(f"malformed PyPI response for {name!r}")
        info = data["info"]

        latest = info.get("version")
        if isinstance(latest, str) and not latest:
            raise ValueError(f"malformed PyPI version for {name!r}")
        latest = latest if isinstance(latest, str) else ""
        if latest:
            try:
                Version(latest)
            except InvalidVersion as exc:
                raise ValueError(f"malformed PyPI version for {name!r}") from exc
        releases = data.get("releases")
        if not isinstance(releases, dict):
            releases = {}
        files = releases.get(latest) or []
        timestamps = [
            parsed
            for f in files
            if isinstance(f, dict)
            and isinstance(upload_time := f.get("upload_time_iso_8601"), str)
            and (parsed := _timestamp(upload_time)) is not None
        ]

        urls = info.get("project_urls")
        pypi_name = info.get("name")
        if isinstance(pypi_name, str) and str(canonicalize_name(pypi_name)) != name:
            raise ValueError(f"mismatched PyPI package name for {name!r}")
        project_urls = (
            {
                key: value
                for key, value in urls.items()
                if isinstance(key, str) and isinstance(value, str)
            }
            if isinstance(urls, dict)
            else {}
        )
        return PackageMetadata(
            name=pypi_name if isinstance(pypi_name, str) else name,
            latest_version=latest,
            license=_license(info),
            last_release=max(timestamps) if timestamps else None,
            project_urls=project_urls,
            yanked_versions=_yanked(releases),
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
        "yanked_versions": list(meta.yanked_versions),
    }


def _timestamp(value: str) -> datetime | None:
    """Parse an ISO 8601 upload timestamp; malformed values are skipped."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _from_cached(data: Any) -> PackageMetadata | None:
    if not isinstance(data, dict):
        raise ValueError("malformed cached PyPI metadata")
    found = data.get("found")
    if not isinstance(found, bool):
        raise ValueError("malformed cached PyPI metadata")
    if not found:
        return None
    name = data["name"]
    latest = data["latest_version"]
    license_ = data.get("license")
    last_release = data.get("last_release")
    project_urls = data.get("project_urls", {})
    yanked_versions = data.get("yanked_versions", [])
    if (
        not isinstance(name, str)
        or not isinstance(latest, str)
        or (license_ is not None and not isinstance(license_, str))
        or (last_release is not None and not isinstance(last_release, str))
        or not isinstance(project_urls, dict)
        or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in project_urls.items()
        )
        or not isinstance(yanked_versions, list)
        or not all(isinstance(version, str) for version in yanked_versions)
    ):
        raise ValueError("malformed cached PyPI metadata")
    canonical_name = str(canonicalize_name(name))
    if not _VALID_NAME_RE.fullmatch(canonical_name):
        raise ValueError("malformed cached PyPI package name")
    if latest:
        try:
            Version(latest)
        except InvalidVersion as exc:
            raise ValueError("malformed cached PyPI version") from exc
    if license_ is not None:
        license_ = _license_value(license_)
    parsed_release = _timestamp(last_release) if last_release else None
    if last_release and parsed_release is None:
        raise ValueError("malformed cached PyPI timestamp")
    return PackageMetadata(
        name=name,
        latest_version=latest,
        license=license_,
        last_release=parsed_release,
        project_urls=project_urls,
        yanked_versions=tuple(yanked_versions),
    )


def _yanked(releases: dict[str, Any]) -> tuple[str, ...]:
    """Versions whose release files were all yanked (PEP 592)."""
    yanked = []
    for version, files in releases.items():
        if not isinstance(files, list) or not files:
            continue
        if all(isinstance(f, dict) and f.get("yanked") is True for f in files):
            yanked.append(version)
    return tuple(yanked)


def _license(info: dict[str, Any]) -> str | None:
    """Best-effort license string from PyPI metadata.

    license_expression (PEP 639) is the most reliable; classifiers come next
    and the free-text license field last.
    """
    expression = info.get("license_expression")
    if isinstance(expression, str) and expression.strip():
        value = _license_value(expression)
        if value is not None:
            return value
    classifiers = info.get("classifiers") or []
    for classifier in classifiers:
        if isinstance(classifier, str) and classifier.startswith("License ::"):
            value = _license_value(classifier.rsplit("::", 1)[-1])
            if value is not None:
                return value
    raw_text = info.get("license")
    text = raw_text.strip() if isinstance(raw_text, str) else ""
    # the free-text field sometimes holds an entire license text blob
    if len(text) > 60 or "\n" in text:
        return None
    return _license_value(text)


def _license_value(value: str) -> str | None:
    value = value.strip()
    return None if not value or value.upper() in _UNKNOWN_LICENSES else value
