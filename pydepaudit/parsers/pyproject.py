"""Parser for pyproject.toml files (PEP 621 dependencies)."""

import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from pydepaudit.models import Dependency


def parse(path: Path) -> list[Dependency]:
    """Extract dependencies from [project].dependencies and optional-dependencies."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project")
    if not isinstance(project, dict):
        return []

    specs = []
    dependencies = project.get("dependencies") or []
    if isinstance(dependencies, list):
        specs.extend(dependencies)
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for extra_deps in optional.values():
            if isinstance(extra_deps, list):
                specs.extend(extra_deps)

    deps = []
    for spec in specs:
        if not isinstance(spec, str):
            continue
        try:
            req = Requirement(spec)
        except InvalidRequirement:
            continue
        deps.append(
            Dependency(name=req.name, specifier=str(req.specifier), source=path.name)
        )
    return deps
