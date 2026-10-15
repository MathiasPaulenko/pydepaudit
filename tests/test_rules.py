from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from pydepaudit.audit import _resolved_version
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
    dep: Dependency = DEP,
) -> AuditResult:
    return AuditResult(
        dependency=dep,
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


def test_license_lgpl_project_still_flags_gpl_dep() -> None:
    # LGPL is weak copyleft — it doesn't make a GPL dependency compatible
    config = Config(project_license="LGPL-2.1")
    findings = evaluate(_result(meta=_meta("GPL-3.0")), config)
    assert [(f.severity, f.kind) for f in findings] == [("high", "license")]


def test_license_dual_permissive_alternative() -> None:
    # dual-licensed: the MIT option means no real incompatibility
    findings = evaluate(_result(meta=_meta("MIT OR GPL-3.0-only")), Config())
    assert findings == []


def test_license_dual_all_denied() -> None:
    findings = evaluate(_result(meta=_meta("GPL-2.0 OR AGPL-3.0")), Config())
    assert [(f.severity, f.kind) for f in findings] == [("high", "license")]


def test_license_mixed_denied_and_weak() -> None:
    findings = evaluate(_result(meta=_meta("GPL-2.0 OR LGPL-2.1")), Config())
    assert [(f.severity, f.kind) for f in findings] == [("medium", "license")]


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


def test_yanked_pinned_version() -> None:
    meta = PackageMetadata("pkg", "2.0", "MIT", None, {}, yanked_versions=("1.0",))
    result = _result(dep=Dependency("pkg", "==1.0"), meta=meta)
    findings = evaluate(result, Config())
    assert [(f.severity, f.kind) for f in findings] == [("medium", "yanked")]


def test_yanked_version_normalization() -> None:
    # '==1.0.0' must match a yanked release listed as '1.0' (PEP 440 equality)
    meta = PackageMetadata("pkg", "2.0", "MIT", None, {}, yanked_versions=("1.0",))
    result = _result(dep=Dependency("pkg", "==1.0.0"), meta=meta)
    findings = evaluate(result, Config())
    assert [(f.severity, f.kind) for f in findings] == [("medium", "yanked")]


def test_yanked_unparseable_pin() -> None:
    meta = PackageMetadata("pkg", "2.0", "MIT", None, {}, yanked_versions=("1.0",))
    result = _result(dep=Dependency("pkg", "===weird-version"), meta=meta)
    findings = evaluate(result, Config())
    assert not any(f.kind == "yanked" for f in findings)


def test_contradictory_pins_are_not_audited_as_installable() -> None:
    dep = Dependency("pkg", "==1.0,>=2.0")
    assert _resolved_version(dep, _meta()) is None
    meta = replace(_meta(), yanked_versions=("1.0",))
    findings = evaluate(_result(meta, dep=dep), Config())
    assert not any(f.kind == "yanked" for f in findings)


def test_ignored_empty_reason_still_ignored() -> None:
    config = Config(ignored={"pkg": ""})
    findings = evaluate(_result(), config)
    assert [f.kind for f in findings] == ["ignored"]


def test_license_word_embedded_mpl_not_flagged() -> None:
    # "SIMPLE" contains "MPL" as a substring — must not be flagged weak copyleft
    findings = evaluate(_result(meta=_meta("Simple License")), Config())
    assert not any(f.kind == "license" and "copyleft" in f.message for f in findings)


def test_license_whitespace_only() -> None:
    findings = evaluate(_result(meta=_meta("   ")), Config())
    assert [(f.severity, f.kind) for f in findings] == [("low", "license")]


@pytest.mark.parametrize("license_", ["UNKNOWN", "NONE", "NOASSERTION"])
def test_license_unknown_sentinel_is_not_permissive(license_: str) -> None:
    findings = evaluate(_result(meta=_meta(license_)), Config())
    assert [(f.severity, f.kind) for f in findings] == [("low", "license")]


def test_yanked_range_not_flagged() -> None:
    # unpinned range — yanked detection only applies to exact pins
    meta = PackageMetadata("pkg", "2.0", "MIT", None, {}, yanked_versions=("1.0",))
    result = _result(dep=Dependency("pkg", ">=1.0"), meta=meta)
    findings = evaluate(result, Config())
    assert findings == []


def test_repo_no_push_date() -> None:
    repo = RepoHealth("u", False, None, 0, 5)
    assert evaluate(_result(repo=repo), Config()) == []


def test_repo_naive_datetime() -> None:
    naive = datetime(2020, 1, 1)  # no tzinfo — must not crash
    repo = RepoHealth("u", False, naive, 0, 1)
    findings = evaluate(_result(repo=repo), Config())
    assert findings[0].kind == "maintainer"


def test_repo_healthy_active() -> None:
    repo = RepoHealth("u", False, datetime.now(UTC), 0, 5)
    assert evaluate(_result(repo=repo), Config()) == []


def test_repo_low_scorecard() -> None:
    repo = RepoHealth("u", False, datetime.now(UTC), 0, 5, scorecard=3.2)
    findings = evaluate(_result(repo=repo), Config())
    assert [(f.severity, f.kind) for f in findings] == [("low", "scorecard")]
    assert "3.2/10" in findings[0].message


def test_repo_good_scorecard_no_finding() -> None:
    repo = RepoHealth("u", False, datetime.now(UTC), 0, 5, scorecard=8.0)
    assert evaluate(_result(repo=repo), Config()) == []


def test_ignored_dependency_case_insensitive() -> None:
    config = Config(ignored={"Pkg": "pinned on purpose"})
    result = _result(vulns=[Vulnerability("V1", "", "critical")])
    findings = evaluate(result, config)
    assert [(f.severity, f.kind) for f in findings] == [("low", "ignored")]


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
