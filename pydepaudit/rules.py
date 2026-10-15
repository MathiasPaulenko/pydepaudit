"""Finding evaluation: turn audit data into severities."""

from datetime import UTC, datetime

from pydepaudit.config import Config
from pydepaudit.models import AuditResult, Finding

SEVERITY_ORDER = ("low", "medium", "high", "critical")

_VULN_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

_WEAK_COPYLEFT = ("LGPL", "MPL", "EPL")


def evaluate(result: AuditResult, config: Config) -> list[Finding]:
    """Apply the audit rules to a dependency and return its findings."""
    if reason := config.ignored.get(result.dependency.name):
        return [Finding("low", "ignored", f"ignored: {reason}")]
    findings = _vulnerability_findings(result)
    findings.extend(_license_findings(result, config))
    findings.extend(_staleness_findings(result, config))
    findings.extend(_repo_findings(result, config))
    return findings


def active_findings(result: AuditResult) -> list[Finding]:
    """Findings that count for status and --fail-on (skips ignored deps)."""
    return [f for f in result.findings if f.kind != "ignored"]


def worst_severity(findings: list[Finding]) -> str | None:
    """Highest severity in *findings*, or None when empty."""
    worst = None
    for finding in findings:
        if worst is None or (
            SEVERITY_ORDER.index(finding.severity) > SEVERITY_ORDER.index(worst)
        ):
            worst = finding.severity
    return worst


def _vulnerability_findings(result: AuditResult) -> list[Finding]:
    findings = []
    for vuln in result.vulnerabilities:
        severity = _VULN_SEVERITY.get(vuln.severity, "low")
        aliases = ", ".join(vuln.aliases[:3])
        label = f" ({aliases})" if aliases else ""
        message = f"{vuln.id}{label} {vuln.summary}".strip()
        findings.append(Finding(severity, "vulnerability", message))
    return findings


def _license_findings(result: AuditResult, config: Config) -> list[Finding]:
    meta = result.metadata
    if meta is None:
        return [Finding("low", "metadata", "not found on PyPI")]
    if not meta.license:
        return [Finding("low", "license", "license unknown")]

    upper = meta.license.upper()
    if config.project_license and _is_copyleft(config.project_license.upper()):
        return []  # copyleft project: copyleft dependencies are compatible
    if any(weak in upper for weak in _WEAK_COPYLEFT):
        return [Finding("medium", "license", f"weak copyleft license: {meta.license}")]
    if any(pattern.upper() in upper for pattern in config.denied_licenses):
        return [Finding("high", "license", f"copyleft license: {meta.license}")]
    return []


def _staleness_findings(result: AuditResult, config: Config) -> list[Finding]:
    meta = result.metadata
    if meta is None or meta.last_release is None:
        return []
    months = _months_since(meta.last_release)
    if months >= config.stale_medium_months:
        return [Finding("medium", "stale", f"stale {months}mo")]
    if months >= config.stale_months:
        return [Finding("low", "stale", f"stale {months}mo")]
    return []


def _repo_findings(result: AuditResult, config: Config) -> list[Finding]:
    repo = result.repo_health
    if repo is None:
        return []
    if repo.archived:
        return [Finding("high", "archived", "upstream repository is archived")]

    months = _months_since(repo.pushed_at) if repo.pushed_at else None
    if months is None or months < config.inactive_months:
        return []
    if repo.contributors == 1:
        return [
            Finding(
                "medium",
                "maintainer",
                f"single contributor, inactive {months}mo",
            )
        ]
    return [Finding("low", "maintainer", f"repository inactive {months}mo")]


def _is_copyleft(license_: str) -> bool:
    return any(word in license_ for word in ("GPL", "AGPL", "SSPL"))


def _months_since(moment: datetime) -> int:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return (datetime.now(UTC) - moment).days // 30
