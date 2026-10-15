"""Terminal and JSON reporting."""

import json
import sys
from datetime import UTC, datetime

from rich.console import Console
from rich.table import Table

from pydepaudit.models import AuditResult

_BAD = {"critical", "high"}
_ICONS = {"fail": "🔴", "warn": "⚠️", "ok": "✅"}


def render_table(results: list[AuditResult]) -> None:
    """Print the audit results as a terminal table."""
    table = Table()
    table.add_column("Package")
    table.add_column("Declared")
    table.add_column("Status")
    table.add_column("Details")

    for result in results:
        dep, meta = result.dependency, result.metadata
        details = "not on PyPI" if meta is None else _details(result)
        table.add_row(dep.name, dep.specifier or "-", _icon(_status(result)), details)
    Console().print(table)


def render_json(results: list[AuditResult]) -> str:
    """Serialize the audit results as JSON."""
    return json.dumps(
        {
            "dependencies": [
                {
                    "name": r.dependency.name,
                    "specifier": r.dependency.specifier,
                    "source": r.dependency.source,
                    "status": _status(r),
                    "latest_version": r.metadata.latest_version if r.metadata else None,
                    "license": r.metadata.license if r.metadata else None,
                    "last_release": (
                        r.metadata.last_release.isoformat()
                        if r.metadata and r.metadata.last_release
                        else None
                    ),
                    "vulnerabilities": [
                        {
                            "id": v.id,
                            "severity": v.severity,
                            "summary": v.summary,
                            "aliases": list(v.aliases),
                            "url": v.url,
                        }
                        for v in r.vulnerabilities
                    ],
                }
                for r in results
            ]
        },
        indent=2,
    )


def _status(result: AuditResult) -> str:
    """Overall status of a dependency: fail, warn or ok."""
    severities = {v.severity for v in result.vulnerabilities}
    if severities & _BAD:
        return "fail"
    if result.vulnerabilities or result.metadata is None:
        return "warn"
    return "ok"


def _utf8() -> bool:
    """Whether stdout can render non-ASCII characters."""
    encoding = getattr(sys.stdout, "encoding", None) or ""
    return "utf" in encoding.lower()


def _icon(status: str) -> str:
    """Emoji for the status, or an ASCII fallback on non-UTF-8 consoles."""
    return _ICONS[status] if _utf8() else status.upper()


def _sep() -> str:
    return " · " if _utf8() else " | "


def _details(result: AuditResult) -> str:
    meta = result.metadata
    assert meta is not None
    if result.vulnerabilities:
        worst = _worst(result)
        vulns = f"{len(result.vulnerabilities)} CVEs ({worst})"
    else:
        vulns = "no CVEs"
    sep = _sep()
    license_ = meta.license or "unknown license"
    return f"{vulns}{sep}{license_}{sep}{_age(meta.last_release)}"


def _worst(result: AuditResult) -> str:
    for severity in ("critical", "high", "medium", "low"):
        if any(v.severity == severity for v in result.vulnerabilities):
            return severity
    return "unknown"


def _age(moment: datetime | None) -> str:
    """Human-friendly age of a release, e.g. '12d ago', '14mo ago'."""
    if moment is None:
        return "unknown age"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    days = (datetime.now(UTC) - moment).days
    if days < 31:
        return f"{days}d ago"
    if days < 365:
        return f"{days // 30}mo ago"
    return f"{days // 365}y ago"
