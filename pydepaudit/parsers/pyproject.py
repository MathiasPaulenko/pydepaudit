"""Parser for pyproject.toml files (PEP 621 dependencies)."""

import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from pydepaudit.models import Dependency
from pydepaudit.parsers.markers import applies_to_env


def parse(path: Path) -> list[Dependency]:
    """Extract dependencies from [project].dependencies and optional-dependencies."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except RecursionError as exc:
        raise ValueError(f"{path} is too deeply nested") from exc
    project = data.get("project")
    if not isinstance(project, dict):
        project = {}

    specs = []
    dependencies = project.get("dependencies") or []
    if isinstance(dependencies, list):
        specs.extend(dependencies)
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for extra_deps in optional.values():
            if isinstance(extra_deps, list):
                specs.extend(extra_deps)

    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for name in groups:
            specs.extend(_expand_group(name, groups, stack=frozenset()))

    deps = []
    seen: set[tuple[str, str]] = set()
    for spec in specs:
        if not isinstance(spec, str):
            continue
        try:
            req = Requirement(spec)
        except (InvalidRequirement, RecursionError):
            continue
        if not applies_to_env(req.marker):
            continue
        identity = (str(canonicalize_name(req.name)), str(req.specifier))
        if identity in seen:
            continue
        seen.add(identity)
        deps.append(
            Dependency(name=req.name, specifier=str(req.specifier), source=path.name)
        )
    return deps


def _expand_group(
    name: str, groups: dict[str, object], stack: frozenset[str]
) -> list[str]:
    """Flatten PEP 735 group inclusions while skipping recursive references."""
    if name in stack:
        return []
    group = groups.get(name)
    if not isinstance(group, list):
        return []
    nested = stack | {name}
    specs = []
    for item in group:
        if isinstance(item, str):
            specs.append(item)
        elif isinstance(item, dict):
            included = item.get("include-group")
            if isinstance(included, str):
                specs.extend(_expand_group(included, groups, nested))
    return specs
