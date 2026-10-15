"""OSV API client (osv.dev — free, no auth)."""

from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pydepaudit.cache import FileCache
from pydepaudit.cvss import base_score, severity_band
from pydepaudit.cvss4 import base_score_v4
from pydepaudit.models import Vulnerability

BASE_URL = "https://api.osv.dev"
_ECOSYSTEM = "PyPI"
# querybatch accepts at most 1000 queries; stay under the limit
_CHUNK_SIZE = 500
_WORKERS = 8

_GHSA_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "LOW": "low",
}


class OSVClient:
    """Query known vulnerabilities for PyPI packages."""

    def __init__(
        self,
        client: httpx.Client | None = None,
        cache: FileCache | None = None,
    ) -> None:
        self._client = client or httpx.Client(
            base_url=BASE_URL, timeout=15.0, follow_redirects=False
        )
        self._cache = cache

    def close(self) -> None:
        """Release the underlying HTTP client resources."""
        self._client.close()

    def query_batch(self, packages: list[tuple[str, str]]) -> list[list[Vulnerability]]:
        """Return vulnerabilities per (name, version), preserving input order.

        The output list always has the same length as *packages*; missing or
        short API results are padded with empty lists. querybatch returns
        trimmed records — full details are hydrated from /v1/vulns/{id}.
        """
        all_raw: list[list[dict[str, Any]]] = []
        for start in range(0, len(packages), _CHUNK_SIZE):
            chunk = packages[start : start + _CHUNK_SIZE]
            queries = [
                {"package": {"name": name, "ecosystem": _ECOSYSTEM}, "version": ver}
                for name, ver in chunk
            ]
            response = self._client.post(
                "/v1/querybatch",
                json={"queries": queries},
                follow_redirects=False,
            )
            response.raise_for_status()
            try:
                payload = response.json()
            except (ValueError, RecursionError) as exc:
                raise ValueError("malformed OSV JSON response") from exc
            results = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(results, list):
                results = []
            # align per chunk: extra results are dropped, missing ones padded —
            # keeps positional mapping even if the API misbehaves
            for r in results[: len(chunk)]:
                vulns = r.get("vulns") if isinstance(r, dict) else None
                all_raw.append(
                    [
                        v
                        for v in vulns
                        if isinstance(v, dict)
                        and isinstance(v.get("id"), str)
                        and v["id"]
                    ]
                    if isinstance(vulns, list)
                    else []
                )
            all_raw.extend([] for _ in range(len(chunk) - len(results)))
        details = self._hydrate(all_raw)
        return [
            _dedupe_vulns(
                [
                    _vulnerability(details.get(str(v.get("id") or ""), v), name)
                    for v in group
                ]
            )
            for group, (name, _) in zip(all_raw[: len(packages)], packages, strict=True)
        ]

    def _hydrate(self, groups: list[list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
        """Fetch full records for trimmed ('lite') vuln entries by id."""
        lite_ids = sorted(
            {
                v["id"]
                for group in groups
                for v in group
                if isinstance(v.get("id"), str) and _is_lite(v)
            }
        )
        details: dict[str, dict[str, Any]] = {}
        if lite_ids:
            with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
                for vuln_id, doc in zip(
                    lite_ids, pool.map(self._fetch_vuln, lite_ids), strict=True
                ):
                    if doc is not None:
                        details[vuln_id] = doc
        return details

    def _fetch_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        key = f"osv:{vuln_id.lower()}"
        if (
            self._cache is not None
            and (cached := self._cache.get(key)) is not None
            and isinstance(cached, dict)
            and cached.get("id") == vuln_id
        ):
            return cached
        try:
            response = self._client.get(
                f"/v1/vulns/{vuln_id}",
                follow_redirects=False,
            )
            if response.status_code != 200:
                return None
            doc = response.json()
        except (httpx.HTTPError, httpx.InvalidURL, ValueError, RecursionError):
            return None  # keep the lite record rather than failing the audit
        if not isinstance(doc, dict) or doc.get("id") != vuln_id:
            return None
        if self._cache is not None:
            self._cache.set(key, doc)
        return doc


# severities ranked for merging duplicates (worst wins)
_SEVERITY_RANK = ("unknown", "none", "low", "medium", "high", "critical")


def _dedupe_vulns(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Merge records describing the same vulnerability (shared id or alias)."""
    index_of: dict[str, int] = {}
    kept: list[Vulnerability | None] = []
    for vuln in vulns:
        identifiers = {vuln.id, *vuln.aliases} - {""}
        # all groups this vuln is linked to — a record bridging two groups
        # must merge both, not just the first one found
        hits = {index_of[i] for i in identifiers if i in index_of}
        if not hits:
            kept.append(vuln)
            idx = len(kept) - 1
        else:
            idx = min(hits)
            for other in sorted(hits - {idx}):
                other_vuln = kept[other]
                if other_vuln is None:
                    raise RuntimeError("vulnerability index points to a merged record")
                vuln = _merge_vuln(other_vuln, vuln)
                kept[other] = None
            primary = kept[idx]
            if primary is None:
                raise RuntimeError("vulnerability index points to a merged record")
            kept[idx] = _merge_vuln(primary, vuln)
            for identifier, group in index_of.items():
                if group in hits:
                    index_of[identifier] = idx
        for identifier in identifiers:
            index_of[identifier] = idx
    return [v for v in kept if v is not None]


def _merge_vuln(a: Vulnerability, b: Vulnerability) -> Vulnerability:
    """Merge duplicate record *b* into *a*: worst severity, union of aliases."""
    vuln_id = a.id or b.id
    aliases = tuple(dict.fromkeys((*a.aliases, b.id, *b.aliases))) or ()
    severity = (
        b.severity
        if _SEVERITY_RANK.index(b.severity) > _SEVERITY_RANK.index(a.severity)
        else a.severity
    )
    return Vulnerability(
        id=vuln_id,
        summary=a.summary or b.summary,
        severity=severity,
        aliases=tuple(x for x in aliases if x and x != vuln_id),
        url=a.url or b.url,
        fixed=_min_version(a.fixed, b.fixed),
    )


def _is_lite(vuln: dict[str, Any]) -> bool:
    """querybatch returns trimmed records: only id/modified, no details."""
    return not any(
        key in vuln for key in ("severity", "database_specific", "summary", "aliases")
    )


def _vulnerability(data: dict[str, Any], package_name: str = "") -> Vulnerability:
    vuln_id = str(data.get("id") or "")
    aliases = data.get("aliases")
    summary = data.get("summary")
    return Vulnerability(
        id=vuln_id,
        summary=summary if isinstance(summary, str) else "",
        severity=_severity(data),
        aliases=(
            tuple(a for a in aliases if isinstance(a, str) and a)
            if isinstance(aliases, list)
            else ()
        ),
        url=f"https://osv.dev/vulnerability/{vuln_id}" if vuln_id else "",
        fixed=_fixed_version(data, package_name),
    )


def _fixed_version(data: dict[str, Any], package_name: str) -> str | None:
    """Earliest version where the vuln is fixed for this package, if known."""
    fixed: list[str] = []
    for affected in data.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict) or package.get("ecosystem") != "PyPI":
            continue
        name = package.get("name")
        if (
            name
            and package_name
            and (
                str(canonicalize_name(str(name)))
                != str(canonicalize_name(package_name))
            )
        ):
            continue
        for range_ in affected.get("ranges") or []:
            if not isinstance(range_, dict):
                continue
            for event in range_.get("events") or []:
                if (
                    isinstance(event, dict)
                    and isinstance(event.get("fixed"), str)
                    and event["fixed"]
                ):
                    fixed.append(event["fixed"])
    return _min_version(*fixed)


def _min_version(*versions: str | None) -> str | None:
    """Smallest parseable version in *versions*, or None."""
    candidates = [v for v in versions if v]
    if not candidates:
        return None
    try:
        return str(min(Version(v) for v in candidates))
    except InvalidVersion:
        return min(candidates)


def _severity(data: dict[str, Any]) -> str:
    """GHSA database severity first, CVSS vector score as fallback."""
    specific = data.get("database_specific")
    label = specific.get("severity") if isinstance(specific, dict) else None
    if isinstance(label, str) and label.upper() in _GHSA_SEVERITY:
        return _GHSA_SEVERITY[label.upper()]
    entries = data.get("severity")
    scores = [
        score
        for entry in (entries if isinstance(entries, list) else [])
        if isinstance(entry, dict) and str(entry.get("type", "")).startswith("CVSS")
        for score in [_cvss_score(str(entry.get("score", "")))]
        if score is not None
    ]
    return severity_band(max(scores) if scores else None)


def _cvss_score(vector: str) -> float | None:
    """Score a CVSS vector of any supported version (3.x or 4.0)."""
    if vector.startswith("CVSS:4"):
        return base_score_v4(vector)
    return base_score(vector)
