import io
import json
from datetime import UTC, datetime, timedelta

import pytest

from pydepaudit import report
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


def test_render_json_includes_repo_health() -> None:
    result = AuditResult(
        dependency=Dependency("pkg", "==1.0"),
        metadata=None,
        repo_health=RepoHealth(
            "https://github.com/a/b", False, None, 3, 7, scorecard=8.5
        ),
    )
    data = json.loads(render_json([result]))
    health = data["dependencies"][0]["repo_health"]
    assert health["contributors"] == 7
    assert health["scorecard"] == 8.5
    assert health["pushed_at"] is None


def test_render_json_never_emits_nonstandard_nan() -> None:
    result = AuditResult(
        dependency=Dependency("pkg"),
        metadata=None,
        repo_health=RepoHealth(
            "https://github.com/a/b", False, None, 0, 0, float("nan")
        ),
    )
    with pytest.raises(ValueError):
        render_json([result])


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


def test_render_table_strips_unsafe_chars(capsys) -> None:
    # untrusted text (dep names, OSV summaries) must not inject ANSI/bidi
    result = AuditResult(
        dependency=Dependency("evil\x1b[2J﻿pkg", "==1.0"),
        metadata=None,
        findings=[Finding("high", "license", "boom\x07\n‏؜pydepaudit")],
    )
    render_table([result])  # must not raise
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "﻿" not in out
    assert "؜" not in out


def test_render_table_does_not_parse_rich_markup(capsys) -> None:
    result = AuditResult(
        dependency=Dependency("[bold red]PWN[/]", "==1.0"),
        metadata=PackageMetadata("pkg", "1.0", "[link=https://evil]pkg[/link]", None),
    )
    render_table([result])
    out = capsys.readouterr().out
    assert "[bold red]PWN[/]" in out
    assert "[link=https://evil]pkg[/link]" in out


def test_sanitize_legacy_encoding_without_mutating_stdout(monkeypatch) -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    monkeypatch.setattr(report.sys, "stdout", stream)
    assert report._sanitize("日本") == r"\u65e5\u672c"
    assert stream.errors == "strict"


def test_render_sarif_omits_empty_location() -> None:
    # Dependency.source defaults to "" — an empty uri is not valid SARIF
    result = AuditResult(
        dependency=Dependency("pkg"),
        metadata=None,
        findings=[Finding("low", "metadata", "not found on PyPI")],
    )
    data = json.loads(render_sarif([result]))
    res = data["runs"][0]["results"][0]
    assert "locations" not in res


def test_render_sarif_escapes_source_uri_and_omits_installed() -> None:
    result = AuditResult(
        dependency=Dependency("pkg", source="deps #1☃.txt"),
        metadata=None,
        findings=[Finding("low", "metadata", "not found")],
    )
    data = json.loads(render_sarif([result]))
    uri = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "deps%20%231%E2%98%83.txt"

    installed = AuditResult(
        dependency=Dependency("pkg", source="installed"),
        metadata=None,
        findings=[Finding("low", "metadata", "not found")],
    )
    data = json.loads(render_sarif([installed]))
    assert "locations" not in data["runs"][0]["results"][0]


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
