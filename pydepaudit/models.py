"""Core data models."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Dependency:
    """A dependency declared by the audited project."""

    name: str
    specifier: str = ""
    source: str = ""


@dataclass(frozen=True)
class PackageMetadata:
    """Relevant PyPI metadata for a package."""

    name: str
    latest_version: str
    license: str | None
    last_release: datetime | None
    project_urls: dict[str, str] = field(default_factory=dict)
    yanked_versions: tuple[str, ...] = ()


@dataclass(frozen=True)
class Vulnerability:
    """A known vulnerability affecting a dependency version."""

    id: str
    summary: str
    severity: str
    aliases: tuple[str, ...] = ()
    url: str = ""
    fixed: str | None = None


@dataclass(frozen=True)
class RepoHealth:
    """Health signals of the upstream repository (usually GitHub)."""

    url: str
    archived: bool
    pushed_at: datetime | None
    open_issues: int
    contributors: int | None
    scorecard: float | None = None  # OpenSSF Scorecard 0-10, None if unrated


@dataclass(frozen=True)
class Finding:
    """A rule violation found during the audit."""

    severity: str
    kind: str
    message: str


@dataclass(frozen=True)
class AuditResult:
    """Everything the audit found for one dependency."""

    dependency: Dependency
    metadata: PackageMetadata | None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    repo_health: RepoHealth | None = None
    findings: list[Finding] = field(default_factory=list)
