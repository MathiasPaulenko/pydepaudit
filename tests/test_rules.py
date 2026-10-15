from dataclasses import replace
from datetime import UTC, datetime, timedelta

from pydepaudit.config import Config
from pydepaudit.models import (
    AuditResult,
    Dependency,
    PackageMetadata,
    RepoHealth,
    Vulnerability,
)
from pydepaudit.rules import active_findings, evaluate, worst_severity

DEP = Dependency(name="pkg", specifier="==1.0", source="requirements.txt")


def _meta(
    license_: str | None = "MIT",
    last_release: datetime | None = None,
) -> PackageMetadata:
    return PackageMetadata(
        name="pkg",
        latest_version="1.0",
        license=license_,
        last_release=last_release or datetime.now(UTC),
    )


def _result(
    meta: PackageMetadata | None = None,
    vulns: list[Vulnerability] | None = None,
    repo: RepoHealth | None = None,
) -> AuditResult:
    return AuditResult(
        dependency=DEP,
        metadata=meta if meta is not None else _meta(),
        vulnerabilities=vulns or [],
        repo_health=repo,
    )


def test_vulnerability_severities() -> None:
    vulns = [
        Vulnerability("V1", "", "critical"),
        Vulnerability("V2", "", "weird"),
    ]
    findings = evaluate(_result(vulns=vulns), Config())
    assert [f.severity for f in findings] == ["critical", "low"]
    assert all(f.kind == "vulnerability" for f in findings)


def test_license_denied() -> None:
    findings = evaluate(_result(meta=_meta("GPL-3.0-only")), Config())
    assert [f.severity for f in findings] == ["high"]
    assert findings[0].kind == "license"


def test_license_weak_copyleft() -> None:
    findings = evaluate(_result(meta=_meta("LGPL-2.1")), Config())
    assert findings[0].severity == "medium"


def test_license_unknown() -> None:
    findings = evaluate(_result(meta=_meta(None)), Config())
    assert [f.kind for f in findings] == ["license"]
    assert findings[0].severity == "low"


def test_license_copyleft_project_allows_copyleft_deps() -> None:
    config = Config(project_license="GPL-3.0")
    findings = evaluate(_result(meta=_meta("GPL-2.0")), config)
    assert findings == []


def test_stale_thresholds() -> None:
    old = datetime.now(UTC) - timedelta(days=20 * 30)
    findings = evaluate(_result(meta=_meta(last_release=old)), Config())
    assert findings[0].severity == "medium"

    mid = datetime.now(UTC) - timedelta(days=14 * 30)
    findings = evaluate(_result(meta=_meta(last_release=mid)), Config())
    assert findings[0].severity == "low"


def test_repo_archived() -> None:
    repo = RepoHealth("u", archived=True, pushed_at=None, open_issues=0, contributors=3)
    findings = evaluate(_result(repo=repo), Config())
    assert [(f.severity, f.kind) for f in findings] == [("high", "archived")]


def test_repo_single_contributor_inactive() -> None:
    old = datetime.now(UTC) - timedelta(days=400)
    repo = RepoHealth("u", archived=False, pushed_at=old, open_issues=0, contributors=1)
    findings = evaluate(_result(repo=repo), Config())
    assert [(f.severity, f.kind) for f in findings] == [("medium", "maintainer")]


def test_repo_inactive_low() -> None:
    old = datetime.now(UTC) - timedelta(days=400)
    repo = RepoHealth("u", archived=False, pushed_at=old, open_issues=0, contributors=8)
    findings = evaluate(_result(repo=repo), Config())
    assert [(f.severity, f.kind) for f in findings] == [("low", "maintainer")]


def test_ignored_dependency() -> None:
    config = Config(ignored={"pkg": "pinned on purpose"})
    result = _result(
        vulns=[Vulnerability("V1", "", "critical")],
        repo=RepoHealth("u", True, None, 0, 1),
    )
    findings = evaluate(result, config)
    assert [(f.severity, f.kind) for f in findings] == [("low", "ignored")]
    result = replace(result, findings=findings)
    assert active_findings(result) == []


def test_worst_severity() -> None:
    assert worst_severity([]) is None
    result = _result(
        meta=_meta("GPL-3.0"),
        vulns=[Vulnerability("V1", "", "critical")],
    )
    findings = evaluate(result, Config())
    assert worst_severity(findings) == "critical"
