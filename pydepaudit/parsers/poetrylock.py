"""Parser for poetry.lock files."""

import tomllib
from pathlib import Path

from pydepaudit.models import Dependency


def parse(path: Path) -> list[Dependency]:
    """Extract pinned dependencies from a poetry.lock file."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except RecursionError as exc:
        raise ValueError(f"{path} is too deeply nested") from exc
    packages = data.get("package")
    if not isinstance(packages, list):
        return []
    deps = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        source = package.get("source")
        if isinstance(source, dict) and source.get("type") in {
            "directory",
            "file",
        }:
            continue  # local/vendored package — meaningless to look up on PyPI
        name = package.get("name")
        if not isinstance(name, str) or not name:
            continue
        version = package.get("version")
        specifier = f"=={version}" if isinstance(version, str) and version else ""
        deps.append(Dependency(name=name, specifier=specifier, source=path.name))
    return deps
