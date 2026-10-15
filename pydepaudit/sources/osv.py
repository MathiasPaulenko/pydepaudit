"""OSV API client (osv.dev — free, no auth)."""

from typing import Any

import httpx

from pydepaudit.cvss import base_score, severity_band
from pydepaudit.models import Vulnerability

BASE_URL = "https://api.osv.dev"
_ECOSYSTEM = "PyPI"

_GHSA_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "LOW": "low",
}


class OSVClient:
    """Query known vulnerabilities for PyPI packages."""

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(base_url=BASE_URL, timeout=15.0)

    def close(self) -> None:
        """Release the underlying HTTP client resources."""
        self._client.close()

    def query_batch(self, packages: list[tuple[str, str]]) -> list[list[Vulnerability]]:
        """Return vulnerabilities per (name, version), preserving input order."""
        if not packages:
            return []
        queries = [
            {"package": {"name": name, "ecosystem": _ECOSYSTEM}, "version": version}
            for name, version in packages
        ]
        response = self._client.post("/v1/querybatch", json={"queries": queries})
        response.raise_for_status()
        results: list[dict[str, Any]] = response.json().get("results", [])
        return [[_vulnerability(v) for v in r.get("vulns") or []] for r in results]


def _vulnerability(data: dict[str, Any]) -> Vulnerability:
    vuln_id = data.get("id", "")
    return Vulnerability(
        id=vuln_id,
        summary=data.get("summary") or "",
        severity=_severity(data),
        aliases=tuple(data.get("aliases") or ()),
        url=f"https://osv.dev/vulnerability/{vuln_id}" if vuln_id else "",
    )


def _severity(data: dict[str, Any]) -> str:
    """GHSA database severity first, CVSS vector score as fallback."""
    label = data.get("database_specific", {}).get("severity")
    if isinstance(label, str) and label.upper() in _GHSA_SEVERITY:
        return _GHSA_SEVERITY[label.upper()]
    scores = [
        score
        for entry in data.get("severity", [])
        if str(entry.get("type", "")).startswith("CVSS")
        for score in [base_score(str(entry.get("score", "")))]
        if score is not None
    ]
    return severity_band(max(scores) if scores else None)
