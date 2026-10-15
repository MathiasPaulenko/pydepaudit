"""Command-line interface for pydepaudit."""

import io
import sys
from dataclasses import replace
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console

from pydepaudit import __version__, report
from pydepaudit.audit import audit_project
from pydepaudit.cache import FileCache
from pydepaudit.config import load
from pydepaudit.parsers import installed as installed_parsers
from pydepaudit.rules import SEVERITY_ORDER, active_findings
from pydepaudit.sources.github import GitHubClient, find_repo
from pydepaudit.sources.osv import OSVClient
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
    # upstream API data can carry any Unicode; never crash on legacy consoles
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="backslashreplace")


@app.command()
def check(
    path: Annotated[
        str,
        typer.Argument(help="Path to the project to audit."),
    ] = ".",
    format_: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table, json or sarif."),
    ] = "table",
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Exit 1 on findings at this severity or above."),
    ] = None,
    license_: Annotated[
        str | None,
        typer.Option("--license", help="Project license for compatibility checks."),
    ] = None,
    no_cache: Annotated[
        bool,
        typer.Option("--no-cache", help="Bypass the local HTTP cache."),
    ] = False,
    installed: Annotated[
        bool,
        typer.Option(
            "--installed",
            help="Audit the packages installed in the current environment.",
        ),
    ] = False,
) -> None:
    """Audit the dependencies of a project."""
    format_ = format_.lower().strip()
    fail_on = fail_on.lower().strip() if fail_on is not None else None
    valid = ", ".join(SEVERITY_ORDER)
    if format_ not in ("table", "json", "sarif"):
        typer.echo(
            f"Invalid --format '{format_}' (expected: table, json, sarif)",
            err=True,
        )
        raise typer.Exit(2)
    if fail_on is not None and fail_on not in SEVERITY_ORDER:
        typer.echo(f"Invalid --fail-on '{fail_on}' (expected: {valid})", err=True)
        raise typer.Exit(2)

    project = Path(path)
    try:
        config = load(project)
    except (OSError, ValueError) as exc:
        typer.echo(f"Invalid .pydepaudit.toml: {exc}", err=True)
        raise typer.Exit(2) from exc
    if license_:
        config = replace(config, project_license=license_)
    cache = None if no_cache else FileCache(project / ".pydepaudit-cache")

    deps = installed_parsers.parse() if installed else None
    try:
        if format_ != "table":
            results = audit_project(project, config=config, cache=cache, deps=deps)
        else:
            with Console(stderr=True).status("Auditing dependencies…"):
                results = audit_project(project, config=config, cache=cache, deps=deps)
    except httpx.HTTPError as exc:
        typer.echo(f"Error contacting an upstream API: {exc}", err=True)
        raise typer.Exit(1) from exc
    except (OSError, ValueError) as exc:
        typer.echo(f"Audit failed: {exc}", err=True)
        raise typer.Exit(1) from exc

    if not results:
        typer.echo(
            "No installed packages found."
            if installed
            else "No dependency files found in the project."
        )
        raise typer.Exit(1)

    if format_ == "json":
        typer.echo(report.render_json(results))
    elif format_ == "sarif":
        typer.echo(report.render_sarif(results))
    else:
        report.render_table(results)

    if fail_on is not None:
        threshold = SEVERITY_ORDER.index(fail_on)
        findings = [
            f
            for r in results
            for f in active_findings(r)
            if SEVERITY_ORDER.index(f.severity) >= threshold
        ]
        if findings:
            raise typer.Exit(1)


@app.command()
def show(
    package: Annotated[str, typer.Argument(help="Dependency name to inspect.")],
) -> None:
    """Show audit details for a single dependency."""
    pypi, osv, github = PyPIClient(), OSVClient(), GitHubClient()
    try:
        meta = pypi.package(package)
        if meta is None:
            typer.echo(f"{package} not found on PyPI.")
            raise typer.Exit(1)

        batch = osv.query_batch([(meta.name, meta.latest_version)])
        vulns = batch[0] if batch else []
        repo = find_repo(meta.project_urls)
        health = github.repo_health(repo) if repo else None
    except httpx.HTTPError as exc:
        typer.echo(f"Error contacting an upstream API: {exc}", err=True)
        raise typer.Exit(1) from exc
    finally:
        for client in (pypi, osv, github):
            client.close()

    typer.echo(f"Name:          {meta.name}")
    typer.echo(f"Latest:        {meta.latest_version}")
    typer.echo(f"License:       {meta.license or 'unknown'}")
    typer.echo(f"Last release:  {meta.last_release or 'unknown'}")
    typer.echo(f"CVEs:          {len(vulns)}")
    for vuln in vulns:
        aliases = ", ".join(vuln.aliases)
        typer.echo(f"  - {vuln.id} [{vuln.severity}] {aliases} {vuln.summary}")
    if health:
        typer.echo(f"Repo:          {health.url}")
        typer.echo(f"Archived:      {health.archived}")
        typer.echo(f"Last push:     {health.pushed_at or 'unknown'}")
        typer.echo(f"Open issues:   {health.open_issues}")
        typer.echo(f"Contributors:  {health.contributors or 'unknown'}")
    for label, url in meta.project_urls.items():
        typer.echo(f"{label}: {url}")
