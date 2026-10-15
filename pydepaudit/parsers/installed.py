"""Parser for the current environment's installed distributions."""

import importlib.metadata

from pydepaudit.models import Dependency


def parse() -> list[Dependency]:
    """Return one dependency per installed distribution, pinned to its version."""
    deps = []
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"]
        version = dist.version
        if name and version:
            deps.append(
                Dependency(name=name, specifier=f"=={version}", source="installed")
            )
    return deps
