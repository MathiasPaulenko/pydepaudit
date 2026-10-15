"""Parser for uv.lock files."""

import tomllib
from pathlib import Path

from pydepaudit.models import Dependency


def parse(path: Path) -> list[Dependency]:
    """Extract pinned dependencies from a uv.lock file.

    Entries with an editable or virtual source are the project itself and are
    skipped.
    """
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
        source = package.get("source", {})
        if isinstance(source, dict) and any(
            kind in source
            for kind in ("editable", "virtual", "workspace", "path", "directory")
        ):
            continue  # project itself or a local package — not a PyPI dep
        name = package.get("name")
        if not isinstance(name, str) or not name:
            continue
        version = package.get("version")
        specifier = f"=={version}" if isinstance(version, str) and version else ""
        deps.append(Dependency(name=name, specifier=specifier, source=path.name))
    return deps
