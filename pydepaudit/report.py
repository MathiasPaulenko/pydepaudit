"""Terminal and JSON reporting."""

import json
from datetime import UTC, datetime

from rich.console import Console
from rich.table import Table

from pydepaudit.models import Dependency, PackageMetadata

Result = tuple[Dependency, PackageMetadata | None]


def render_table(results: list[Result]) -> None:
    """Print the audit results as a terminal table."""
    table = Table()
    table.add_column("Package")
    table.add_column("Declared")
    table.add_column("Latest")
    table.add_column("License")
    table.add_column("Last release")

    for dep, meta in results:
        if meta is None:
            table.add_row(dep.name, dep.specifier or "-", "-", "-", "not on PyPI")
            continue
        table.add_row(
            meta.name,
            dep.specifier or "-",
            meta.latest_version,
            meta.license or "unknown",
            _age(meta.last_release),
        )
    Console().print(table)


def render_json(results: list[Result]) -> str:
    """Serialize the audit results as JSON."""
    return json.dumps(
        {
            "dependencies": [
                {
                    "name": dep.name,
                    "specifier": dep.specifier,
                    "source": dep.source,
                    "latest_version": meta.latest_version if meta else None,
                    "license": meta.license if meta else None,
                    "last_release": (
                        meta.last_release.isoformat()
                        if meta and meta.last_release
                        else None
                    ),
                }
                for dep, meta in results
            ]
        },
        indent=2,
    )


def _age(moment: datetime | None) -> str:
    """Human-friendly age of a release, e.g. '12d ago', '14mo ago'."""
    if moment is None:
        return "unknown"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    days = (datetime.now(UTC) - moment).days
    if days < 31:
        return f"{days}d ago"
    if days < 365:
        return f"{days // 30}mo ago"
    return f"{days // 365}y ago"
