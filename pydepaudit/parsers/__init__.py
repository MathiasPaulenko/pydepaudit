"""Dependency parsers for requirements.txt, pyproject.toml and lock files."""

from collections.abc import Callable
from pathlib import Path

from pydepaudit.models import Dependency
from pydepaudit.parsers import poetrylock, pyproject, requirements, uvlock

# In priority order: lock files first since they carry exact versions.
_PARSERS: list[tuple[str, Callable[[Path], list[Dependency]]]] = [
    ("uv.lock", uvlock.parse),
    ("poetry.lock", poetrylock.parse),
    ("requirements.txt", requirements.parse),
    ("pyproject.toml", pyproject.parse),
]


def parse_project(path: Path) -> list[Dependency]:
    """Return dependencies declared in the first known file found in *path*."""
    for filename, parse in _PARSERS:
        candidate = path / filename
        if candidate.is_file():
            return parse(candidate)
    return []
