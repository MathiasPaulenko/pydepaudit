"""Parser for pyproject.toml files (PEP 621 dependencies)."""

import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from pydepaudit.models import Dependency
from pydepaudit.parsers.markers import applies_to_env


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

    # PEP 735 dependency groups (uv, pip>=25) — string items only; table
    # entries like {include-group = "x"} carry no direct requirements
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group in groups.values():
            if isinstance(group, list):
                specs.extend(item for item in group if isinstance(item, str))

    deps = []
    for spec in specs:
        if not isinstance(spec, str):
            continue
        try:
            req = Requirement(spec)
        except InvalidRequirement:
            continue
        if not applies_to_env(req.marker):
            continue
        deps.append(
            Dependency(name=req.name, specifier=str(req.specifier), source=path.name)
        )
    return deps
