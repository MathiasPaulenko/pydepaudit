import json
from datetime import UTC, datetime, timedelta

from pydepaudit.models import (
    AuditResult,
    Dependency,
    Finding,
    PackageMetadata,
    RepoHealth,
    Vulnerability,
)
from pydepaudit.report import render_json, render_sarif, render_table


def _result() -> AuditResult:
    return AuditResult(
        dependency=Dependency("pkg", ">=1.0", "requirements.txt"),
        metadata=PackageMetadata(
            name="pkg",
            latest_version="2.0",
            license="MIT",
            last_release=None,
            project_urls={},
        ),
        vulnerabilities=[Vulnerability("GHSA-1", "bug", "high", ("CVE-1",))],
        repo_health=RepoHealth("https://x", False, None, 3, 12),
        findings=[Finding("high", "vulnerability", "GHSA-1 bug")],
    )


def test_render_json_structure() -> None:
    data = json.loads(render_json([_result()]))
    dep = data["dependencies"][0]
    assert dep["name"] == "pkg"
    assert dep["status"] == "fail"
    assert dep["vulnerabilities"][0]["id"] == "GHSA-1"
    assert dep["findings"][0]["severity"] == "high"


def test_render_json_empty() -> None:
    assert json.loads(render_json([])) == {"dependencies": []}


def test_render_sarif() -> None:
    data = json.loads(render_sarif([_result()]))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "pydepaudit"
    assert run["tool"]["driver"]["rules"][0]["id"] == "pydepaudit/vulnerability"
    res = run["results"][0]
    assert res["level"] == "error"  # high severity maps to error
    assert "GHSA-1" in res["message"]["text"]
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "requirements.txt"
    )


def test_render_sarif_empty() -> None:
    data = json.loads(render_sarif([]))
    assert data["runs"][0]["results"] == []


def test_render_table_ignored(tmp_path) -> None:
    result = _result()
    result = AuditResult(
        dependency=result.dependency,
        metadata=None,
        findings=[Finding("low", "ignored", "ignored: vendored")],
    )
    render_table([result])  # must not crash on missing metadata


def test_render_table_ok(capsys) -> None:
    render_table([_result()])
    out = capsys.readouterr().out
    assert "pkg" in out
    assert "GHSA-1" in out
    assert "1 high" in out


def test_render_table_clean_row(capsys) -> None:
    result = AuditResult(
        dependency=Dependency("clean", ">=1.0"),
        metadata=PackageMetadata(
            name="clean",
            latest_version="1.2",
            license="MIT",
            last_release=datetime.now(UTC),
            project_urls={},
        ),
        repo_health=RepoHealth("https://x", False, None, 0, 42),
    )
    render_table([result])
    out = capsys.readouterr().out
    assert "no CVEs" in out
    assert "MIT" in out
    assert "42" in out  # contributors


def test_age_branches(capsys) -> None:
    now = datetime.now(UTC)
    cases = [
        (None, "unknown age"),
        (now - timedelta(days=10), "10d ago"),
        (now - timedelta(days=90), "3mo ago"),
        (now - timedelta(days=800), "2y ago"),
        (datetime(2024, 1, 1), None),  # naive datetime: no crash
        (now + timedelta(days=5), "0d ago"),  # future timestamp clamped
    ]
    for moment, expected in cases:
        result = AuditResult(
            dependency=Dependency("x", ""),
            metadata=PackageMetadata("x", "1.0", None, moment),
        )
        render_table([result])
        out = capsys.readouterr().out
        if expected is not None:
            assert expected in out
