"""Terminal and JSON reporting."""

import json
import sys
from datetime import UTC, datetime

from rich.console import Console
from rich.table import Table

from pydepaudit.models import AuditResult
from pydepaudit.rules import active_findings, worst_severity

_ICONS = {"fail": "🔴", "warn": "⚠️", "ok": "✅"}


def render_table(results: list[AuditResult]) -> None:
    """Print the audit results as a terminal table."""
    console = Console()
    table = Table()
    table.add_column("Package")
    table.add_column("Declared")
    table.add_column("Status")
    table.add_column("Details")

    for result in results:
        dep = result.dependency
        table.add_row(
            dep.name, dep.specifier or "-", _icon(_status(result)), _details(result)
        )
    console.print(table)

    counts: dict[str, int] = {}
    for result in results:
        for finding in active_findings(result):
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
    if counts:
        parts = ", ".join(
            f"{counts[sev]} {sev}"
            for sev in ("critical", "high", "medium", "low")
            if sev in counts
        )
        console.print(f"{sum(counts.values())} findings: {parts}")


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
                            "fixed": v.fixed,
                        }
                        for v in r.vulnerabilities
                    ],
                    "findings": [
                        {
                            "severity": f.severity,
                            "kind": f.kind,
                            "message": f.message,
                        }
                        for f in r.findings
                    ],
                }
                for r in results
            ]
        },
        indent=2,
    )


def _status(result: AuditResult) -> str:
    """Overall status of a dependency: fail, warn or ok."""
    if any(f.kind == "ignored" for f in result.findings):
        return "ok"
    worst = worst_severity(active_findings(result))
    if worst in ("critical", "high"):
        return "fail"
    if worst is not None or result.metadata is None:
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


_MAX_DETAILS = 4


def _details(result: AuditResult) -> str:
    ignored = [f for f in result.findings if f.kind == "ignored"]
    if ignored:
        return ignored[0].message

    meta = result.metadata
    if meta is None:
        return "not on PyPI"

    sep = _sep()
    findings = active_findings(result)
    if findings:
        shown = sep.join(f.message for f in findings[:_MAX_DETAILS])
        remaining = len(findings) - _MAX_DETAILS
        return shown if remaining <= 0 else f"{shown}{sep}+{remaining} more"

    license_ = meta.license or "unknown license"
    parts = ["no CVEs", license_, _age(meta.last_release)]
    if result.repo_health and result.repo_health.contributors is not None:
        parts.append(f"{result.repo_health.contributors} contributors")
    return sep.join(parts)


def _age(moment: datetime | None) -> str:
    """Human-friendly age of a release, e.g. '12d ago', '14mo ago'."""
    if moment is None:
        return "unknown age"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    days = max(0, (datetime.now(UTC) - moment).days)
    if days < 31:
        return f"{days}d ago"
    if days < 365:
        return f"{days // 30}mo ago"
    return f"{days // 365}y ago"
