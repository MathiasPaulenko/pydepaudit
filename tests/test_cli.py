import json
from pathlib import Path

import httpx
import respx
from typer.testing import CliRunner

from pydepaudit import __version__
from pydepaudit.cli import app
from pydepaudit.models import Dependency

runner = CliRunner()

REQUESTS_JSON = {
    "info": {
        "name": "requests",
        "version": "2.32.3",
        "license_expression": "Apache-2.0",
        "classifiers": [],
        "project_urls": {},
    },
    "releases": {"2.32.3": [{"upload_time_iso_8601": "2024-05-29T15:37:47Z"}]},
}


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
def test_check_table_with_vuln(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    osv_route = respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-xxxx",
                                "summary": "Bad",
                                "aliases": ["CVE-2024-1"],
                                "database_specific": {"severity": "HIGH"},
                            }
                        ]
                    }
                ]
            },
        )
    )
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 0
    assert "requests" in result.output
    assert "GHSA-xxxx" in result.output
    assert "findings: 1 high" in result.output
    # the declared pin, not the latest PyPI version, is what gets audited
    body = json.loads(osv_route.calls.last.request.content)
    assert body["queries"][0]["version"] == "2.31.0"


@respx.mock
def test_check_json(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests>=2\n")
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    osv_route = respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
    )
    result = runner.invoke(app, ["check", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    assert '"name": "requests"' in result.output
    assert '"license": "Apache-2.0"' in result.output
    # unversioned specifiers fall back to the latest PyPI release
    body = json.loads(osv_route.calls.last.request.content)
    assert body["queries"][0]["version"] == "2.32.3"


@respx.mock
def test_check_sarif(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests>=2\n")
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
    )
    result = runner.invoke(app, ["check", str(tmp_path), "--format", "sarif"])
    assert result.exit_code == 0
    assert json.loads(result.output)["version"] == "2.1.0"


@respx.mock
def test_check_fail_on(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-xxxx",
                                "summary": "Bad",
                                "database_specific": {"severity": "HIGH"},
                            }
                        ]
                    }
                ]
            },
        )
    )
    result = runner.invoke(app, ["check", str(tmp_path), "--fail-on", "high"])
    assert result.exit_code == 1
    result = runner.invoke(app, ["check", str(tmp_path), "--fail-on", "HIGH"])
    assert result.exit_code == 1
    result = runner.invoke(app, ["check", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 0


def test_check_invalid_options(tmp_path: Path) -> None:
    # invalid flags are rejected before any network call
    result = runner.invoke(app, ["check", str(tmp_path), "--fail-on", "bogus"])
    assert result.exit_code == 2
    result = runner.invoke(app, ["check", str(tmp_path), "--format", "xml"])
    assert result.exit_code == 2


def test_check_malformed_toml(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("not = [valid toml\n")
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 1
    assert "Audit failed" in result.output


@respx.mock
def test_check_network_error(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests\n")
    respx.get("https://pypi.org/pypi/requests/json").mock(
        side_effect=httpx.ConnectError("no network")
    )
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 1
    assert "Error contacting" in result.output


@respx.mock
def test_check_arbitrary_equality_pin(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests===2.31.0\n")
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    osv_route = respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
    )
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 0
    body = json.loads(osv_route.calls.last.request.content)
    assert body["queries"][0]["version"] == "2.31.0"


@respx.mock
def test_check_ignored_dependency(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / ".pydepaudit.toml").write_text('[ignore]\nrequests = "vendored"\n')
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-xxxx",
                                "summary": "Bad",
                                "database_specific": {"severity": "CRITICAL"},
                            }
                        ]
                    }
                ]
            },
        )
    )
    result = runner.invoke(app, ["check", str(tmp_path), "--fail-on", "low"])
    assert result.exit_code == 0
    assert "ignored: vendored" in result.output


@respx.mock
def test_show(tmp_path: Path) -> None:
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(200, json=REQUESTS_JSON)
    )
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
    )
    result = runner.invoke(app, ["show", "requests"])
    assert result.exit_code == 0
    assert "requests" in result.output
    assert "CVEs:          0" in result.output


@respx.mock
def test_show_not_found() -> None:
    respx.get("https://pypi.org/pypi/ghost/json").mock(return_value=httpx.Response(404))
    result = runner.invoke(app, ["show", "ghost"])
    assert result.exit_code == 1
    assert "not found" in result.output


@respx.mock
def test_show_network_error() -> None:
    respx.get("https://pypi.org/pypi/x/json").mock(
        side_effect=httpx.ConnectError("down")
    )
    result = runner.invoke(app, ["show", "x"])
    assert result.exit_code == 1
    assert "Error contacting" in result.output


@respx.mock
def test_show_full_output() -> None:
    payload = {
        "info": {
            "name": "pkg",
            "version": "1.0",
            "license_expression": "MIT",
            "project_urls": {"Source": "https://github.com/owner/repo"},
        },
        "releases": {"1.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}]},
    }
    respx.get("https://pypi.org/pypi/pkg/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-1",
                                "summary": "bug",
                                "aliases": ["CVE-1"],
                                "database_specific": {"severity": "HIGH"},
                            }
                        ]
                    }
                ]
            },
        )
    )
    respx.get("https://api.github.com/repos/owner/repo").mock(
        return_value=httpx.Response(
            200,
            json={
                "archived": False,
                "pushed_at": "2025-06-01T00:00:00Z",
                "open_issues_count": 7,
            },
        )
    )
    respx.get("https://api.github.com/repos/owner/repo/contributors").mock(
        return_value=httpx.Response(200, json=[{"login": "a"}])
    )
    result = runner.invoke(app, ["show", "pkg"])
    assert result.exit_code == 0
    assert "GHSA-1 [high] CVE-1" in result.output
    assert "owner/repo" in result.output
    assert "Open issues:   7" in result.output


@respx.mock
def test_check_installed(tmp_path: Path, monkeypatch) -> None:
    from pydepaudit.parsers import installed as installed_parsers

    monkeypatch.setattr(
        installed_parsers,
        "parse",
        lambda: [Dependency("pkg", "==1.0", "installed")],
    )
    payload = {
        "info": {"name": "pkg", "version": "1.0", "license_expression": "MIT"},
        "releases": {"1.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}]},
    }
    respx.get("https://pypi.org/pypi/pkg/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
    )
    # no dependency file exists in tmp_path — --installed must still work
    result = runner.invoke(app, ["check", str(tmp_path), "--installed"])
    assert result.exit_code == 0
    assert "pkg" in result.output


@respx.mock
def test_check_with_repo_health(tmp_path: Path) -> None:
    payload = {
        "info": {
            "name": "pkg",
            "version": "1.0",
            "license_expression": "MIT",
            "project_urls": {"Source": "https://github.com/owner/repo"},
        },
        "releases": {"1.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}]},
    }
    (tmp_path / "requirements.txt").write_text("pkg==1.0\n")
    respx.get("https://pypi.org/pypi/pkg/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
    )
    respx.get("https://api.github.com/repos/owner/repo").mock(
        return_value=httpx.Response(
            200,
            json={
                "archived": True,
                "pushed_at": "2024-01-01T00:00:00Z",
                "open_issues_count": 3,
            },
        )
    )
    respx.get("https://api.github.com/repos/owner/repo/contributors").mock(
        return_value=httpx.Response(200, json=[{"login": "a"}])
    )
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 0
    assert "archived" in result.output


def test_check_license_override(tmp_path: Path) -> None:
    (tmp_path / ".pydepaudit.toml").write_text("stale_months = 999\n")
    (tmp_path / "requirements.txt").write_text("")
    result = runner.invoke(app, ["check", str(tmp_path), "--license", "MIT"])
    assert result.exit_code == 1  # no deps found, but override parsed fine


def test_check_invalid_config(tmp_path: Path) -> None:
    (tmp_path / ".pydepaudit.toml").write_text("stale_months = [\n")
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 2
    assert ".pydepaudit.toml" in result.output


@respx.mock
def test_check_not_on_pypi(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("ghostpkg==1.0\n")
    respx.get("https://pypi.org/pypi/ghostpkg/json").mock(
        return_value=httpx.Response(404)
    )
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
    )
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 0
    assert "not on PyPI" in result.output


@respx.mock
def test_check_many_findings_truncated(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("COLUMNS", "300")  # wide console: no cell wrapping
    vulns = [
        {"id": f"GHSA-{i}", "summary": f"vuln {i}", "aliases": []} for i in range(6)
    ]
    payload = {
        "info": {"name": "pkg", "version": "1.0", "license_expression": "MIT"},
        "releases": {"1.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}]},
    }
    (tmp_path / "requirements.txt").write_text("pkg==1.0\n")
    respx.get("https://pypi.org/pypi/pkg/json").mock(
        return_value=httpx.Response(200, json=payload)
    )
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": vulns}]})
    )
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 0
    # 6 vulns + 1 stale finding → first 4 shown, rest summarized
    assert "+3 more" in result.output


@respx.mock
def test_check_skips_unresolvable(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("ghostpkg\n")
    respx.get("https://pypi.org/pypi/ghostpkg/json").mock(
        return_value=httpx.Response(404)
    )
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 0
    assert "not on PyPI" in result.output
