"""Terminal, JSON and SARIF reporting."""

import contextlib
import json
import re
import sys
from datetime import UTC, datetime
from urllib.parse import quote

from rich.console import Console
from rich.table import Table
from rich.text import Text

from pydepaudit import __version__
from pydepaudit.models import AuditResult
from pydepaudit.rules import active_findings, worst_severity

_ICONS = {"fail": "🔴", "warn": "⚠️", "ok": "✅"}

# control chars, ANSI escapes and bidi/zero-width marks — dep names and OSV
# summaries are untrusted text and could otherwise inject escape sequences
_UNSAFE_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u061c\ufeff\u200b-\u200f\u202a-\u202e\u2066-\u206f]"
)


def _sanitize(text: str) -> str:
    """Strip characters that could corrupt or hijack a terminal."""
    clean = _UNSAFE_RE.sub("", str(text))
    encoding = getattr(sys.stdout, "encoding", None)
    if encoding:
        with contextlib.suppress(LookupError):
            clean = clean.encode(encoding, "backslashreplace").decode(encoding)
    return clean


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
            Text(_sanitize(dep.name)),
            Text(_sanitize(dep.specifier or "-")),
            Text(_icon(_status(result))),
            Text(_details(result)),
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
                    "repo_health": (
                        {
                            "url": r.repo_health.url,
                            "archived": r.repo_health.archived,
                            "pushed_at": (
                                r.repo_health.pushed_at.isoformat()
                                if r.repo_health.pushed_at
                                else None
                            ),
                            "open_issues": r.repo_health.open_issues,
                            "contributors": r.repo_health.contributors,
                            "scorecard": r.repo_health.scorecard,
                        }
                        if r.repo_health
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
        allow_nan=False,
    )


_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def render_sarif(results: list[AuditResult]) -> str:
    """Serialize findings as SARIF 2.1.0 for GitHub code scanning upload."""
    rules: dict[str, dict[str, object]] = {}
    sarif_results = []
    for result in results:
        dep = result.dependency
        for finding in result.findings:
            rule_id = f"pydepaudit/{finding.kind}"
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": finding.kind,
                    "shortDescription": {"text": f"{finding.kind} finding"},
                },
            )
            sarif_result: dict[str, object] = {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": f"{dep.name}: {finding.message}"},
                "properties": {
                    "package": dep.name,
                    "severity": finding.severity,
                },
            }
            uri = _artifact_uri(dep.source)
            if uri:
                sarif_result["locations"] = [
                    {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                ]
            sarif_results.append(sarif_result)
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pydepaudit",
                            "version": __version__,
                            "informationUri": (
                                "https://github.com/MathiasPaulenko/pydepaudit"
                            ),
                            "rules": list(rules.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
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


def _artifact_uri(source: str) -> str | None:
    """Encode a source filename as a valid SARIF URI; installed is not a file."""
    if not source or source == "installed":
        return None
    return quote(source.replace("\\", "/"), safe="/:@-._~")


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
        return _sanitize(ignored[0].message)

    meta = result.metadata
    if meta is None:
        return "not on PyPI"

    sep = _sep()
    findings = active_findings(result)
    if findings:
        shown = sep.join(_sanitize(f.message) for f in findings[:_MAX_DETAILS])
        remaining = len(findings) - _MAX_DETAILS
        return shown if remaining <= 0 else f"{shown}{sep}+{remaining} more"

    license_ = meta.license or "unknown license"
    parts = ["no CVEs", _sanitize(license_), _age(meta.last_release)]
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
