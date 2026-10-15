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


@dataclass(frozen=True)
class Vulnerability:
    """A known vulnerability affecting a dependency version."""

    id: str
    summary: str
    severity: str
    aliases: tuple[str, ...] = ()
    url: str = ""


@dataclass(frozen=True)
class AuditResult:
    """Everything the audit found for one dependency."""

    dependency: Dependency
    metadata: PackageMetadata | None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
