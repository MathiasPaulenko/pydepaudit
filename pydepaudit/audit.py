"""Audit orchestration: parse project, query sources, evaluate rules."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from pydepaudit.cache import FileCache
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

_WORKERS = 8


def audit_project(
    path: Path,
    config: Config | None = None,
    cache: FileCache | None = None,
    pypi: PyPIClient | None = None,
    osv: OSVClient | None = None,
    github: GitHubClient | None = None,
) -> list[AuditResult]:
    """Audit every declared dependency of the project at *path*."""
    deps = _dedupe(parse_project(path))
    if not deps:
        return []

    owned: list[PyPIClient | OSVClient | GitHubClient] = []
    if pypi is None:
        pypi = PyPIClient(cache=cache)
        owned.append(pypi)
    if osv is None:
        osv = OSVClient()
        owned.append(osv)
    if github is None:
        github = GitHubClient(cache=cache)
        owned.append(github)

    try:
        return _audit(deps, config or load(path), pypi, osv, github)
    finally:
        for client in owned:
            client.close()


def _audit(
    deps: list[Dependency],
    config: Config,
    pypi: PyPIClient,
    osv: OSVClient,
    github: GitHubClient,
) -> list[AuditResult]:
    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        metas = list(pool.map(pypi.package, [d.name for d in deps]))

    resolved = [
        (index, version)
        for index, (dep, meta) in enumerate(zip(deps, metas, strict=True))
        if (version := _resolved_version(dep, meta))
    ]

    vulns: dict[int, list[Vulnerability]] = {}
    if resolved:
        batch = osv.query_batch([(deps[i].name, v) for i, v in resolved])
        for (index, _), found in zip(resolved, batch, strict=True):
            vulns[index] = found

    healths = _repo_healths(metas, github)

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


def _dedupe(deps: list[Dependency]) -> list[Dependency]:
    """Keep the first declaration per normalized package name."""
    seen: dict[str, Dependency] = {}
    for dep in deps:
        seen.setdefault(str(canonicalize_name(dep.name)), dep)
    return list(seen.values())


def _resolved_version(dep: Dependency, meta: PackageMetadata | None) -> str | None:
    """Version to audit: the declared pin if exact, else the latest release."""
    for spec in SpecifierSet(dep.specifier):
        if spec.operator in ("==", "===") and "*" not in spec.version:
            return spec.version
    return meta.latest_version if meta else None


def _repo_healths(
    metas: list[PackageMetadata | None], github: GitHubClient
) -> list[RepoHealth | None]:
    """Repo health per metadata, fetching each upstream repo once."""
    repos = [find_repo(meta.project_urls) if meta else None for meta in metas]
    unique = sorted({repo for repo in repos if repo is not None})
    health_map: dict[str, RepoHealth | None] = {}
    if unique:
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            for repo, health in zip(
                unique, pool.map(github.repo_health, unique), strict=True
            ):
                health_map[repo] = health
    return [health_map[repo] if repo is not None else None for repo in repos]
