"""Command-line interface for pydepaudit."""

from typing import Annotated

import typer

from pydepaudit import __version__

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
    typer.echo("check is not implemented yet.")


@app.command()
def show(
    package: Annotated[str, typer.Argument(help="Dependency name to inspect.")],
) -> None:
    """Show audit details for a single dependency."""
    typer.echo(f"show {package} is not implemented yet.")
