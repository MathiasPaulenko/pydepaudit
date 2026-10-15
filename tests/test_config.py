from pathlib import Path

from pydepaudit.config import detect_project_license, load


def test_load_defaults(tmp_path: Path) -> None:
    config = load(tmp_path)
    assert config.stale_months == 12
    assert config.stale_medium_months == 18
    assert config.denied_licenses == ("GPL", "AGPL", "SSPL")
    assert config.ignored == {}
    assert config.project_license is None


def test_load_full(tmp_path: Path) -> None:
    (tmp_path / ".pydepaudit.toml").write_text(
        "stale_months = 6\n"
        "stale_medium_months = 24\n"
        "inactive_months = 9\n"
        'project_license = "MIT"\n'
        'denied_licenses = ["GPL"]\n\n'
        "[ignore]\n"
        'requests = "transient dep, removed in v2"\n'
    )
    config = load(tmp_path)
    assert config.stale_months == 6
    assert config.stale_medium_months == 24
    assert config.inactive_months == 9
    assert config.project_license == "MIT"
    assert config.denied_licenses == ("GPL",)
    assert config.ignored == {"requests": "transient dep, removed in v2"}


def test_detect_license_pyproject_spdx(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nlicense = "GPL-3.0-only"\n'
    )
    assert detect_project_license(tmp_path) == "GPL-3.0-only"


def test_detect_license_file(tmp_path: Path) -> None:
    (tmp_path / "LICENSE").write_text("MIT License\n\nCopyright (c) 2026\n")
    assert detect_project_license(tmp_path) == "MIT"


def test_detect_license_none(tmp_path: Path) -> None:
    assert detect_project_license(tmp_path) is None
