"""Parser for pyproject.toml files (PEP 621 dependencies)."""

import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from pydepaudit.models import Dependency


def parse(path: Path) -> list[Dependency]:
    """Extract dependencies from [project].dependencies and optional-dependencies."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    project = data.get("project", {})
    specs = list(project.get("dependencies", []))
    for extra_deps in project.get("optional-dependencies", {}).values():
        specs.extend(extra_deps)

    deps = []
    for spec in specs:
        try:
            req = Requirement(spec)
        except InvalidRequirement:
            continue
        deps.append(
            Dependency(name=req.name, specifier=str(req.specifier), source=path.name)
        )
    return deps
