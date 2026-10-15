"""Parser for requirements.txt files."""

import re
from dataclasses import replace
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from pydepaudit.models import Dependency
from pydepaudit.parsers.markers import applies_to_env

# A comment marker is '#' at line start or preceded by whitespace — a bare '#'
# inside the line can be part of a URL fragment (e.g. 'pkg @ https://x#sha=..').
_COMMENT_RE = re.compile(r"(?:^|\s)#")

# pip options that can appear inline after a requirement (e.g. pip-compile
# output appends '--hash=sha256:...'); they are not part of the PEP 508 spec.
_OPTION_RE = re.compile(r"\s+--\S+")


def parse(path: Path) -> list[Dependency]:
    """Extract requirements declared in a requirements.txt-style file.

    Follows ``-r``/``--requirement`` includes recursively (cycle-safe).
    ``-c``/``--constraint`` files contribute version pins applied to declared
    dependencies, as pip does — they never introduce new dependencies.
    """
    deps: list[Dependency] = []
    constraints: dict[str, str] = {}
    _collect(path, deps, constraints, seen=set(), as_constraint=False)
    return [replace(dep, specifier=_apply(dep, constraints)) for dep in deps]


def _collect(
    path: Path,
    deps: list[Dependency],
    constraints: dict[str, str],
    seen: set[Path],
    as_constraint: bool,
) -> None:
    resolved = path.resolve()
    if resolved in seen or not resolved.is_file():
        return
    seen.add(resolved)
    try:
        text = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return

    for raw in _logical_lines(text):
        line = _COMMENT_RE.split(raw, maxsplit=1)[0].strip()
        if not line:
            continue
        include = _include_target(line)
        if include is not None:
            target, constraint = include
            _collect(
                resolved.parent / target,
                deps,
                constraints,
                seen,
                as_constraint=constraint,
            )
            continue
        line = _OPTION_RE.split(line, maxsplit=1)[0].strip()
        if not line or line.startswith("-"):
            continue
        try:
            req = Requirement(line)
        except InvalidRequirement:
            continue
        if not applies_to_env(req.marker):
            continue
        if as_constraint:
            name = str(canonicalize_name(req.name))
            spec = str(req.specifier)
            previous = constraints.get(name)
            constraints[name] = f"{previous},{spec}" if previous else spec
        else:
            deps.append(
                Dependency(
                    name=req.name,
                    specifier=str(req.specifier),
                    source=resolved.name,
                )
            )


def _include_target(line: str) -> tuple[str, bool] | None:
    """Return (path, is_constraint) for -r/-c lines, else None."""
    head, _, arg = line.partition(" ")
    arg = arg.strip()
    if "=" in head:
        head, _, eq_arg = head.partition("=")
        arg = arg or eq_arg.strip()
    if head in ("-r", "--requirement"):
        pass
    elif head.startswith("-r") and not head.startswith("--"):
        arg = arg or head[2:]
    elif head in ("-c", "--constraint"):
        return (arg, True) if arg else None
    else:
        return None
    arg = arg.strip()
    return (arg, False) if arg else None


def _apply(dep: Dependency, constraints: dict[str, str]) -> str:
    """Specifier with the matching constraint AND-ed in, pip-style."""
    extra = constraints.get(str(canonicalize_name(dep.name)))
    if not extra:
        return dep.specifier
    return f"{dep.specifier},{extra}".lstrip(",")


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
