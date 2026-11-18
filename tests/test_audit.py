from datetime import UTC, datetime
from pathlib import Path

import pytest

from pydepaudit.audit import _resolved_version
from pydepaudit.models import Dependency, PackageMetadata


def test_audit_project_accepts_str_path(tmp_path: Path, monkeypatch) -> None:
    # the public entry point coerces str paths instead of raising TypeError
    import pydepaudit.audit as audit_mod

    seen: list[object] = []
    monkeypatch.setattr(
        audit_mod, "parse_project", lambda path: seen.append(path) or []
    )
    assert audit_mod.audit_project(str(tmp_path)) == []
    assert isinstance(seen[0], Path)


def _meta(**overrides) -> PackageMetadata:
    defaults = {
        "name": "pkg",
        "latest_version": "9.9.9",
        "license": "MIT",
        "last_release": datetime.now(UTC),
        "releases": ("1.0.0", "1.0.5", "1.1.0", "2.0.0", "9.9.9"),
    }
    return PackageMetadata(**{**defaults, **overrides})


def test_wildcard_pin_audits_newest_matching_release() -> None:
    # '==1.0.*' can never install 9.9.9 — audit the newest 1.0.x instead
    assert _resolved_version(Dependency("pkg", "==1.0.*"), _meta()) == "1.0.5"


def test_upper_bound_audits_newest_release_inside_range() -> None:
    assert _resolved_version(Dependency("pkg", ">=1.0,<2.0"), _meta()) == "1.1.0"


def test_compatible_release_operator_resolves_inside_range() -> None:
    # ~=1.0 means >=1.0, ==1.* — 1.1.0 satisfies it
    assert _resolved_version(Dependency("pkg", "~=1.0"), _meta()) == "1.1.0"


def test_range_admitting_latest_still_audits_latest() -> None:
    assert _resolved_version(Dependency("pkg", ">=2"), _meta()) == "9.9.9"


def test_no_specifier_audits_latest() -> None:
    assert _resolved_version(Dependency("pkg", ""), _meta()) == "9.9.9"


def test_exact_pin_wins_over_release_selection() -> None:
    assert _resolved_version(Dependency("pkg", "==1.0.0"), _meta()) == "1.0.0"


def test_prereleases_not_selected_for_plain_ranges() -> None:
    meta = _meta(releases=("1.0.0", "2.0.0", "3.0.0rc1"))
    assert _resolved_version(Dependency("pkg", ">=1.0"), meta) == "2.0.0"


def test_prerelease_range_selects_prerelease() -> None:
    meta = _meta(releases=("1.0.0", "3.0.0rc1"))
    assert _resolved_version(Dependency("pkg", ">=3.0.0rc1"), meta) == "3.0.0rc1"


def test_yanked_releases_excluded_from_range_selection() -> None:
    meta = _meta(
        releases=("1.0.0", "1.0.5", "9.9.9"),
        yanked_versions=("1.0.5", "9.9.9"),
    )
    assert _resolved_version(Dependency("pkg", ">=1.0"), meta) == "1.0.0"


def test_yanked_latest_skipped_without_specifier() -> None:
    meta = _meta(releases=("1.0.0", "9.9.9"), yanked_versions=("9.9.9",))
    assert _resolved_version(Dependency("pkg", ""), meta) == "1.0.0"


def test_exact_pin_to_yanked_version_still_audited() -> None:
    # an exact pin installs the yanked release — it must be audited (and the
    # yanked rule flags it separately)
    meta = _meta(releases=("1.0.0", "9.9.9"), yanked_versions=("9.9.9",))
    assert _resolved_version(Dependency("pkg", "==9.9.9"), meta) == "9.9.9"


def test_unparseable_releases_are_ignored() -> None:
    meta = _meta(releases=("1.0.0", "garbage", "2.0.0"))
    assert _resolved_version(Dependency("pkg", ">=1.5"), meta) == "2.0.0"


def test_no_matching_release_falls_back_to_latest() -> None:
    meta = _meta(releases=("1.0.0",))
    assert _resolved_version(Dependency("pkg", ">=99"), meta) == "9.9.9"


def test_missing_release_list_falls_back_to_latest() -> None:
    # cache entries written before the releases field existed
    meta = _meta(releases=())
    assert _resolved_version(Dependency("pkg", "==1.0.*"), meta) == "9.9.9"


def test_none_metadata_resolves_to_none() -> None:
    assert _resolved_version(Dependency("pkg", "==1.0"), None) is None


def test_invalid_specifier_falls_back_to_latest() -> None:
    assert _resolved_version(Dependency("pkg", "==1.0 oops"), _meta()) == "9.9.9"


@pytest.mark.parametrize(
    ("specifier", "expected"),
    [
        ("==1.0,>=2.0", None),  # contradictory pins: not installable
        ("===weird-version", None),  # unparseable pin
    ],
)
def test_uninstallable_pins_are_not_audited(
    specifier: str, expected: str | None
) -> None:
    assert _resolved_version(Dependency("pkg", specifier), _meta()) == expected
