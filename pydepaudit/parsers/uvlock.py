"""Parser for uv.lock files."""

import tomllib
from pathlib import Path

from pydepaudit.models import Dependency


def parse(path: Path) -> list[Dependency]:
    """Extract pinned dependencies from a uv.lock file.

    Entries with an editable or virtual source are the project itself and are
    skipped.
    """
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    deps = []
    for package in data.get("package", []):
        source = package.get("source", {})
        if isinstance(source, dict) and ("editable" in source or "virtual" in source):
            continue
        name = package.get("name")
        if not name:
            continue
        version = package.get("version")
        specifier = f"=={version}" if version else ""
        deps.append(Dependency(name=name, specifier=specifier, source=path.name))
    return deps
