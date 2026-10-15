"""Audit orchestration: parse project, query sources, build results."""

from pathlib import Path

from packaging.specifiers import SpecifierSet

from pydepaudit.models import AuditResult, Dependency, PackageMetadata, Vulnerability
from pydepaudit.parsers import parse_project
from pydepaudit.sources.osv import OSVClient
from pydepaudit.sources.pypi import PyPIClient


def audit_project(
    path: Path,
    pypi: PyPIClient | None = None,
    osv: OSVClient | None = None,
) -> list[AuditResult]:
    """Audit every declared dependency of the project at *path*."""
    deps = parse_project(path)
    if not deps:
        return []

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

    return [
        AuditResult(dependency=dep, metadata=meta, vulnerabilities=vulns.get(i, []))
        for i, (dep, meta) in enumerate(zip(deps, metas, strict=True))
    ]


def _resolved_version(dep: Dependency, meta: PackageMetadata | None) -> str | None:
    """Version to audit: the declared pin if exact, else the latest release."""
    for spec in SpecifierSet(dep.specifier):
        if spec.operator == "==" and "*" not in spec.version:
            return spec.version
    return meta.latest_version if meta else None
