from pathlib import Path

import httpx
import respx
from typer.testing import CliRunner

from pydepaudit import __version__
from pydepaudit.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "check" in result.output
    assert "show" in result.output


def test_check_no_dependency_files(tmp_path: Path) -> None:
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 1
    assert "No dependency files" in result.output


@respx.mock
def test_check_table(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {
                    "name": "requests",
                    "version": "2.32.3",
                    "license_expression": "Apache-2.0",
                    "classifiers": [],
                    "project_urls": {},
                },
                "releases": {
                    "2.32.3": [{"upload_time_iso_8601": "2024-05-29T15:37:47Z"}]
                },
            },
        )
    )
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 0
    assert "requests" in result.output
    assert "Apache-2.0" in result.output


@respx.mock
def test_check_json(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {
                    "name": "requests",
                    "version": "2.32.3",
                    "license_expression": "Apache-2.0",
                    "classifiers": [],
                    "project_urls": {},
                },
                "releases": {"2.32.3": []},
            },
        )
    )
    result = runner.invoke(app, ["check", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    assert '"name": "requests"' in result.output
    assert '"license": "Apache-2.0"' in result.output
