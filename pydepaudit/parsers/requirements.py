"""Parser for requirements.txt files."""

import re
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from pydepaudit.models import Dependency

# A comment marker is '#' at line start or preceded by whitespace — a bare '#'
# inside the line can be part of a URL fragment (e.g. 'pkg @ https://x#sha=..').
_COMMENT_RE = re.compile(r"(?:^|\s)#")

# pip options that can appear inline after a requirement (e.g. pip-compile
# output appends '--hash=sha256:...'); they are not part of the PEP 508 spec.
_OPTION_RE = re.compile(r"\s+--\S+")


def parse(path: Path) -> list[Dependency]:
    """Extract requirements declared in a requirements.txt-style file."""
    deps = []
    for raw in _logical_lines(path.read_text(encoding="utf-8")):
        line = _COMMENT_RE.split(raw, maxsplit=1)[0]
        line = _OPTION_RE.split(line, maxsplit=1)[0].strip()
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


def _logical_lines(text: str) -> list[str]:
    """Join lines ending in a backslash continuation, as pip does."""
    lines = []
    buf = ""
    for raw in text.splitlines():
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        lines.append(buf + stripped)
        buf = ""
    if buf:
        lines.append(buf)
    return lines
