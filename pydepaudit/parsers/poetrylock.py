"""Parser for poetry.lock files."""

import tomllib
from pathlib import Path

from pydepaudit.models import Dependency


def parse(path: Path) -> list[Dependency]:
    """Extract pinned dependencies from a poetry.lock file."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    deps = []
    for package in data.get("package", []):
        name = package.get("name")
        if not name:
            continue
        version = package.get("version")
        specifier = f"=={version}" if version else ""
        deps.append(Dependency(name=name, specifier=specifier, source=path.name))
    return deps
