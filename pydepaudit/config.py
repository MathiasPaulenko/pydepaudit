"""Loading of .pydepaudit.toml configuration."""

import tomllib
from dataclasses import dataclass, field
from math import isfinite
from pathlib import Path
from typing import Any

CONFIG_FILENAME = ".pydepaudit.toml"

DEFAULT_DENIED_LICENSES = ("GPL", "AGPL", "SSPL")

# License-file signatures used for autodetection, checked in order.
_LICENSE_SIGNATURES = (
    ("GNU AFFERO", "AGPL"),
    ("GNU LESSER", "LGPL"),
    ("GNU GENERAL PUBLIC", "GPL"),
    ("APACHE LICENSE", "Apache-2.0"),
    ("MIT LICENSE", "MIT"),
    ("BSD", "BSD"),
)


@dataclass(frozen=True)
class Config:
    """Audit thresholds and policy, from .pydepaudit.toml or defaults."""

    stale_months: int = 12
    stale_medium_months: int = 18
    inactive_months: int = 12
    scorecard_min: float = 5.0  # OpenSSF Scorecard threshold for a finding
    project_license: str | None = None
    denied_licenses: tuple[str, ...] = DEFAULT_DENIED_LICENSES
    ignored: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("stale_months", "stale_medium_months", "inactive_months"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.stale_medium_months < self.stale_months:
            raise ValueError("stale_medium_months must be >= stale_months")
        score = self.scorecard_min
        if isinstance(score, bool) or not isinstance(score, int | float):
            finite_score = False
        else:
            try:
                finite_score = isfinite(score)
            except OverflowError:
                finite_score = False
        if (
            isinstance(score, bool)
            or not isinstance(score, int | float)
            or not finite_score
            or not 0 <= score <= 10
        ):
            raise ValueError("scorecard_min must be a finite number from 0 to 10")
        if not isinstance(self.denied_licenses, tuple) or not all(
            isinstance(pattern, str) and pattern.strip()
            for pattern in self.denied_licenses
        ):
            raise ValueError("denied_licenses must be a tuple of license names")
        if self.project_license is not None and (
            not isinstance(self.project_license, str)
            or not self.project_license.strip()
        ):
            raise ValueError("project_license must be a non-empty string or None")
        if not isinstance(self.ignored, dict) or not all(
            isinstance(name, str) and isinstance(reason, str)
            for name, reason in self.ignored.items()
        ):
            raise ValueError("ignored must map package names to string reasons")


def load(path: Path) -> Config:
    """Read .pydepaudit.toml from *path*; defaults when the file is absent."""
    file = path / CONFIG_FILENAME
    if not file.is_file():
        data: dict[str, Any] = {}
    else:
        try:
            data = tomllib.loads(file.read_text(encoding="utf-8"))
        except RecursionError as exc:
            raise ValueError("configuration TOML is too deeply nested") from exc

    license_ = data.get("project_license")
    if not isinstance(license_, str) or not license_.strip():
        license_ = detect_project_license(path)
    elif license_:
        license_ = license_.strip()
    ignored = data.get("ignore")
    if ignored is not None and not isinstance(ignored, dict):
        raise ValueError("ignore must be a table of package names to reasons")
    return Config(
        stale_months=_number(data, "stale_months", 12, int),
        stale_medium_months=_number(data, "stale_medium_months", 18, int),
        inactive_months=_number(data, "inactive_months", 12, int),
        scorecard_min=_number(data, "scorecard_min", 5.0, float),
        project_license=license_,
        denied_licenses=_denied(data),
        ignored=ignored or {},
    )


def _number(data: dict[str, Any], key: str, default: Any, cast: Any) -> Any:
    """Validate numeric config values without accepting coercible strings."""
    raw = data.get(key, default)
    valid_type = (
        type(raw) is int
        if cast is int
        else isinstance(raw, int | float) and not isinstance(raw, bool)
    )
    if not valid_type:
        raise ValueError(f"{key} must be a number, got {raw!r}")
    try:
        return cast(raw)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{key} must be a number, got {raw!r}") from exc


def _denied(data: dict[str, Any]) -> tuple[str, ...]:
    raw = data.get("denied_licenses", DEFAULT_DENIED_LICENSES)
    if isinstance(raw, str) or not isinstance(raw, (list, tuple)):
        raise ValueError("denied_licenses must be a list of license names")
    if not all(isinstance(x, str) for x in raw):
        raise ValueError("denied_licenses must be a list of license names")
    return tuple(pattern for x in raw if (pattern := x.strip()))


def detect_project_license(path: Path) -> str | None:
    """Best-effort license detection from the audited project's pyproject/LICENSE."""
    pyproject = path / "pyproject.toml"
    license_file = None
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, RecursionError, tomllib.TOMLDecodeError):
            data = {}
        project = data.get("project")
        declared = project.get("license") if isinstance(project, dict) else None
        if isinstance(declared, str) and declared.strip():
            return declared.strip()  # SPDX expression (PEP 639)
        if isinstance(declared, dict):
            text = declared.get("text")
            if isinstance(text, str) and text.strip():
                return text.strip()
            if isinstance(declared.get("file"), str):
                license_file = path / declared["file"]

    if license_file is None:
        for candidate in ("LICENSE", "LICENSE.txt", "LICENSE.md"):
            if (path / candidate).is_file():
                license_file = path / candidate
                break
    if license_file is None or not license_file.is_file():
        return None

    try:
        # only the header matters — don't slurp a giant file into memory
        with license_file.open("rb") as fh:
            head = fh.read(8192).decode("utf-8", errors="replace").upper()
    except OSError:
        return None
    for signature, name in _LICENSE_SIGNATURES:
        if signature in head:
            return name
    return None
