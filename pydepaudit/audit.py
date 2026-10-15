"""Audit orchestration: parse project, query sources, evaluate rules."""

from dataclasses import replace
from pathlib import Path

from packaging.specifiers import SpecifierSet

from pydepaudit.config import Config, load
from pydepaudit.models import (
    AuditResult,
    Dependency,
    PackageMetadata,
    RepoHealth,
    Vulnerability,
)
from pydepaudit.parsers import parse_project
from pydepaudit.rules import evaluate
from pydepaudit.sources.github import GitHubClient, find_repo
from pydepaudit.sources.osv import OSVClient
from pydepaudit.sources.pypi import PyPIClient


def audit_project(
    path: Path,
    config: Config | None = None,
    pypi: PyPIClient | None = None,
    osv: OSVClient | None = None,
    github: GitHubClient | None = None,
) -> list[AuditResult]:
    """Audit every declared dependency of the project at *path*."""
    deps = parse_project(path)
    if not deps:
        return []

    config = config or load(path)
    pypi = pypi or PyPIClient()
    metas = [pypi.package(dep.name) for dep in deps]

    resolved = [
        (index, version)
        for index, (dep, meta) in enumerate(zip(deps, metas, strict=True))
        if (version := _resolved_version(dep, meta)) is not None
    ]

    vulns: dict[int, list[Vulnerability]] = {}
    if resolved:
        osv = osv or OSVClient()
        batch = osv.query_batch([(deps[i].name, v) for i, v in resolved])
        for (index, _), found in zip(resolved, batch, strict=True):
            vulns[index] = found

    healths = _repo_healths(metas, github or GitHubClient())

    results = []
    for i, (dep, meta) in enumerate(zip(deps, metas, strict=True)):
        result = AuditResult(
            dependency=dep,
            metadata=meta,
            vulnerabilities=vulns.get(i, []),
            repo_health=healths[i],
        )
        results.append(replace(result, findings=evaluate(result, config)))
    return results


def _resolved_version(dep: Dependency, meta: PackageMetadata | None) -> str | None:
    """Version to audit: the declared pin if exact, else the latest release."""
    for spec in SpecifierSet(dep.specifier):
        if spec.operator == "==" and "*" not in spec.version:
            return spec.version
    return meta.latest_version if meta else None


def _repo_healths(
    metas: list[PackageMetadata | None], github: GitHubClient
) -> list[RepoHealth | None]:
    """Repo health per metadata, deduplicating repeated upstream repos."""
    cache: dict[str, RepoHealth | None] = {}
    healths: list[RepoHealth | None] = []
    for meta in metas:
        repo = find_repo(meta.project_urls) if meta else None
        if repo is None:
            healths.append(None)
            continue
        if repo not in cache:
            cache[repo] = github.repo_health(repo)
        healths.append(cache[repo])
    return healths
