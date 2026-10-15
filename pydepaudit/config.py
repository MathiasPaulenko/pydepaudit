"""Loading of .pydepaudit.toml configuration."""

import tomllib
from dataclasses import dataclass, field
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
    project_license: str | None = None
    denied_licenses: tuple[str, ...] = DEFAULT_DENIED_LICENSES
    ignored: dict[str, str] = field(default_factory=dict)


def load(path: Path) -> Config:
    """Read .pydepaudit.toml from *path*; defaults when the file is absent."""
    file = path / CONFIG_FILENAME
    if not file.is_file():
        data: dict[str, Any] = {}
    else:
        data = tomllib.loads(file.read_text(encoding="utf-8"))

    license_ = data.get("project_license") or detect_project_license(path)
    return Config(
        stale_months=int(data.get("stale_months", 12)),
        stale_medium_months=int(data.get("stale_medium_months", 18)),
        inactive_months=int(data.get("inactive_months", 12)),
        project_license=license_ if isinstance(license_, str) else None,
        denied_licenses=tuple(data.get("denied_licenses", DEFAULT_DENIED_LICENSES)),
        ignored=dict(data.get("ignore", {})),
    )


def detect_project_license(path: Path) -> str | None:
    """Best-effort license detection from the audited project's pyproject/LICENSE."""
    pyproject = path / "pyproject.toml"
    license_file = None
    if pyproject.is_file():
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        declared = data.get("project", {}).get("license")
        if isinstance(declared, str):
            return declared  # SPDX expression (PEP 639)
        if isinstance(declared, dict):
            if isinstance(declared.get("text"), str):
                return str(declared["text"])
            if isinstance(declared.get("file"), str):
                license_file = path / declared["file"]

    if license_file is None:
        for candidate in ("LICENSE", "LICENSE.txt", "LICENSE.md"):
            if (path / candidate).is_file():
                license_file = path / candidate
                break
    if license_file is None or not license_file.is_file():
        return None

    head = license_file.read_text(encoding="utf-8", errors="replace")[:4096].upper()
    for signature, name in _LICENSE_SIGNATURES:
        if signature in head:
            return name
    return None
