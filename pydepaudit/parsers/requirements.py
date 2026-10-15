"""Parser for requirements.txt files."""

import re
import shlex
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
    _collect(path, deps, constraints, seen=set(), as_constraint=False, nested=False)
    return [replace(dep, specifier=_apply(dep, constraints)) for dep in deps]


def _collect(
    path: Path,
    deps: list[Dependency],
    constraints: dict[str, str],
    seen: set[tuple[Path, bool]],
    as_constraint: bool,
    nested: bool,
) -> None:
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError, ValueError):
        if not nested:
            raise
        return  # unresolvable include target (e.g. embedded NUL)
    visit = (resolved, as_constraint)
    if visit in seen or not resolved.is_file():
        return
    seen.add(visit)
    try:
        text = resolved.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        if nested:
            return  # missing/unreadable includes are tolerated
        raise  # the file being parsed unreadable is an error, not "no deps"

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
                # pip semantics: an -r inside a constraint file is still a
                # constraint file — it must not introduce new dependencies
                as_constraint=as_constraint or constraint,
                nested=True,
            )
            continue
        line = _OPTION_RE.split(line, maxsplit=1)[0].strip()
        if not line or line.startswith("-"):
            continue
        try:
            req = Requirement(line)
        except (InvalidRequirement, RecursionError):
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
    try:
        parts = shlex.split(line)
    except ValueError:
        return None
    if not parts:
        return None
    head = parts[0]
    arg = parts[1] if len(parts) > 1 else ""
    if "=" in head:
        head, _, attached_arg = head.partition("=")
        arg = attached_arg or arg
    if head in ("-r", "--requirement"):
        is_constraint = False
    elif head in ("-c", "--constraint"):
        is_constraint = True
    elif head.startswith("-r") and not head.startswith("--"):
        arg = arg or head[2:]
        is_constraint = False
    elif head.startswith("-c") and not head.startswith("--"):
        arg = arg or head[2:]
        is_constraint = True
    else:
        return None
    # an include line can carry trailing pip options (e.g. -r f.txt --hash=...)
    arg = _OPTION_RE.split(arg, maxsplit=1)[0].strip()
    return (arg, is_constraint) if arg else None


def _apply(dep: Dependency, constraints: dict[str, str]) -> str:
    """Specifier with the matching constraint AND-ed in, pip-style."""
    extra = constraints.get(str(canonicalize_name(dep.name)))
    if not extra:
        return dep.specifier
    parts = (part.strip() for part in f"{dep.specifier},{extra}".split(","))
    return ",".join(dict.fromkeys(part for part in parts if part))


def _logical_lines(text: str) -> list[str]:
    """Join lines ending in a backslash continuation, as pip does."""
    lines: list[str] = []
    parts: list[str] = []
    for raw in text.splitlines():
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            parts.extend((stripped[:-1], " "))
            continue
        parts.append(stripped)
        lines.append("".join(parts))
        parts.clear()
    if parts:
        lines.append("".join(parts))
    return lines
