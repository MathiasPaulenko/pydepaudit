"""OSV API client (osv.dev — free, no auth)."""

from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from pydepaudit.cache import FileCache
from pydepaudit.cvss import base_score, severity_band
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
            base_url=BASE_URL, timeout=15.0, follow_redirects=True
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
            response = self._client.post("/v1/querybatch", json={"queries": queries})
            response.raise_for_status()
            results = response.json().get("results") or []
            all_raw.extend(
                [v for v in (r.get("vulns") or []) if isinstance(v, dict)]
                for r in results
            )
        all_raw.extend([] for _ in range(len(packages) - len(all_raw)))
        details = self._hydrate(all_raw)
        return [
            _dedupe_vulns(
                [_vulnerability(details.get(str(v.get("id") or ""), v)) for v in group]
            )
            for group in all_raw[: len(packages)]
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
        if self._cache is not None and (cached := self._cache.get(key)) is not None:
            return cached if isinstance(cached, dict) else None
        try:
            response = self._client.get(f"/v1/vulns/{vuln_id}")
            if response.status_code != 200:
                return None
            doc = response.json()
        except httpx.HTTPError:
            return None  # keep the lite record rather than failing the audit
        if isinstance(doc, dict) and self._cache is not None:
            self._cache.set(key, doc)
        return doc if isinstance(doc, dict) else None


# severities ranked for merging duplicates (worst wins)
_SEVERITY_RANK = ("unknown", "none", "low", "medium", "high", "critical")


def _dedupe_vulns(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Merge records describing the same vulnerability (shared id or alias)."""
    index_of: dict[str, int] = {}
    kept: list[Vulnerability] = []
    for vuln in vulns:
        identifiers = {vuln.id, *vuln.aliases} - {""}
        hit = next((index_of[i] for i in identifiers if i in index_of), None)
        if hit is None:
            kept.append(vuln)
            hit = len(kept) - 1
        else:
            kept[hit] = _merge_vuln(kept[hit], vuln)
        for identifier in identifiers:
            index_of[identifier] = hit
    return kept


def _merge_vuln(a: Vulnerability, b: Vulnerability) -> Vulnerability:
    """Merge duplicate record *b* into *a*: worst severity, union of aliases."""
    aliases = tuple(dict.fromkeys((*a.aliases, b.id, *b.aliases))) or ()
    severity = (
        b.severity
        if _SEVERITY_RANK.index(b.severity) > _SEVERITY_RANK.index(a.severity)
        else a.severity
    )
    return Vulnerability(
        id=a.id,
        summary=a.summary or b.summary,
        severity=severity,
        aliases=tuple(x for x in aliases if x != a.id),
        url=a.url or b.url,
    )


def _is_lite(vuln: dict[str, Any]) -> bool:
    """querybatch returns trimmed records: only id/modified, no details."""
    return not any(
        key in vuln for key in ("severity", "database_specific", "summary", "aliases")
    )


def _vulnerability(data: dict[str, Any]) -> Vulnerability:
    vuln_id = str(data.get("id") or "")
    aliases = data.get("aliases")
    summary = data.get("summary")
    return Vulnerability(
        id=vuln_id,
        summary=str(summary) if summary else "",
        severity=_severity(data),
        aliases=tuple(str(a) for a in aliases) if isinstance(aliases, list) else (),
        url=f"https://osv.dev/vulnerability/{vuln_id}" if vuln_id else "",
    )


def _severity(data: dict[str, Any]) -> str:
    """GHSA database severity first, CVSS vector score as fallback."""
    label = data.get("database_specific", {}).get("severity")
    if isinstance(label, str) and label.upper() in _GHSA_SEVERITY:
        return _GHSA_SEVERITY[label.upper()]
    entries = data.get("severity")
    scores = [
        score
        for entry in (entries if isinstance(entries, list) else [])
        if isinstance(entry, dict) and str(entry.get("type", "")).startswith("CVSS")
        for score in [base_score(str(entry.get("score", "")))]
        if score is not None
    ]
    return severity_band(max(scores) if scores else None)
