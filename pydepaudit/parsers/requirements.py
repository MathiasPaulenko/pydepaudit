"""Parser for requirements.txt files."""

import re
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from pydepaudit.models import Dependency

# A comment marker is '#' at line start or preceded by whitespace — a bare '#'
# inside the line can be part of a URL fragment (e.g. 'pkg @ https://x#sha=..').
_COMMENT_RE = re.compile(r"(?:^|\s)#")


def parse(path: Path) -> list[Dependency]:
    """Extract requirements declared in a requirements.txt-style file."""
    deps = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = _COMMENT_RE.split(raw, maxsplit=1)[0].strip()
        if not line or line.startswith("-"):
            continue
        try:
            req = Requirement(line)
        except InvalidRequirement:
            continue
        deps.append(
            Dependency(name=req.name, specifier=str(req.specifier), source=path.name)
        )
    return deps
