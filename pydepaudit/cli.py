"""Command-line interface for pydepaudit."""

from pathlib import Path
from typing import Annotated

import typer

from pydepaudit import __version__, report
from pydepaudit.parsers import parse_project
from pydepaudit.sources.pypi import PyPIClient

app = typer.Typer(
    name="pydepaudit",
    help="Audit dependencies for CVEs, licenses, staleness and maintainer health.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"pydepaudit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", "-V", callback=_version_callback, is_eager=True),
    ] = False,
) -> None:
    """pydepaudit entrypoint."""


@app.command()
def check(
    path: Annotated[
        str,
        typer.Argument(help="Path to the project to audit."),
    ] = ".",
    format_: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table or json."),
    ] = "table",
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Exit 1 on findings at this severity or above."),
    ] = None,
) -> None:
    """Audit the dependencies of a project."""
    deps = parse_project(Path(path))
    if not deps:
        typer.echo("No dependency files found in the project.")
        raise typer.Exit(1)

    client = PyPIClient()
    results = [(dep, client.package(dep.name)) for dep in deps]

    if format_ == "json":
        typer.echo(report.render_json(results))
    else:
        report.render_table(results)


@app.command()
def show(
    package: Annotated[str, typer.Argument(help="Dependency name to inspect.")],
) -> None:
    """Show audit details for a single dependency."""
    meta = PyPIClient().package(package)
    if meta is None:
        typer.echo(f"{package} not found on PyPI.")
        raise typer.Exit(1)

    typer.echo(f"Name:          {meta.name}")
    typer.echo(f"Latest:        {meta.latest_version}")
    typer.echo(f"License:       {meta.license or 'unknown'}")
    typer.echo(f"Last release:  {meta.last_release or 'unknown'}")
    for label, url in meta.project_urls.items():
        typer.echo(f"{label}: {url}")
