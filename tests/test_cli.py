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


def test_check_stub() -> None:
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 0
    assert "not implemented" in result.output
