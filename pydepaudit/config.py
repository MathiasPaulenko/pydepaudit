"""Loading of .pydepaudit.toml configuration."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_FILENAME = ".pydepaudit.toml"

DEFAULT_DENIED_LICENSES = ("GPL", "AGPL", "SSPL")


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
        return Config()
    data = tomllib.loads(file.read_text(encoding="utf-8"))
    return Config(
        stale_months=int(data.get("stale_months", 12)),
        stale_medium_months=int(data.get("stale_medium_months", 18)),
        inactive_months=int(data.get("inactive_months", 12)),
        project_license=data.get("project_license"),
        denied_licenses=tuple(data.get("denied_licenses", DEFAULT_DENIED_LICENSES)),
        ignored=dict(data.get("ignore", {})),
    )
