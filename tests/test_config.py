from pathlib import Path

import pytest

from pydepaudit.config import Config, detect_project_license, load


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


def test_detect_license_pyproject_text_form(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nlicense = { text = "Apache-2.0" }\n'
    )
    assert detect_project_license(tmp_path) == "Apache-2.0"


def test_detect_license_pyproject_file_ref(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nlicense = { file = "COPYING" }\n'
    )
    (tmp_path / "COPYING").write_text("GNU GENERAL PUBLIC LICENSE\nVersion 3\n")
    assert detect_project_license(tmp_path) == "GPL"


def test_detect_license_broken_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project\nbroken = [")
    assert detect_project_license(tmp_path) is None


def test_blank_declared_license_falls_back_to_license_file(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nlicense = "   "\n'
    )
    (tmp_path / "LICENSE").write_text("MIT License\n")
    assert detect_project_license(tmp_path) == "MIT"


def test_detect_license_unrecognized_file(tmp_path: Path) -> None:
    (tmp_path / "LICENSE").write_text("Some proprietary text without signatures\n")
    assert detect_project_license(tmp_path) is None


def test_load_denied_licenses_string_rejected(tmp_path: Path) -> None:
    # a bare string would silently become per-character patterns ("G","P","L")
    (tmp_path / ".pydepaudit.toml").write_text('denied_licenses = "GPL"\n')
    with pytest.raises(ValueError, match="denied_licenses"):
        load(tmp_path)


def test_load_denied_licenses_rejects_non_strings(tmp_path: Path) -> None:
    (tmp_path / ".pydepaudit.toml").write_text('denied_licenses = [42, "GPL"]\n')
    with pytest.raises(ValueError, match="denied_licenses"):
        load(tmp_path)


def test_load_invalid_numeric_type(tmp_path: Path) -> None:
    (tmp_path / ".pydepaudit.toml").write_text("stale_months = []\n")
    with pytest.raises(ValueError, match="stale_months"):
        load(tmp_path)

    (tmp_path / ".pydepaudit.toml").write_text("stale_months = true\n")
    with pytest.raises(ValueError, match="stale_months"):
        load(tmp_path)


def test_load_deeply_nested_toml_is_clean_error(tmp_path: Path) -> None:
    (tmp_path / ".pydepaudit.toml").write_text(
        "value = " + "[" * 2000 + "0" + "]" * 2000
    )
    with pytest.raises(ValueError, match="too deeply nested"):
        load(tmp_path)


def test_load_invalid_project_license_falls_back(tmp_path: Path) -> None:
    # a non-string project_license must not skip license-file detection
    (tmp_path / ".pydepaudit.toml").write_text("project_license = 42\n")
    (tmp_path / "LICENSE").write_text("MIT License\n\nCopyright (c) 2026\n")
    assert load(tmp_path).project_license == "MIT"


def test_load_blank_project_license_falls_back(tmp_path: Path) -> None:
    (tmp_path / ".pydepaudit.toml").write_text('project_license = "   "\n')
    (tmp_path / "LICENSE").write_text("MIT License\n")
    assert load(tmp_path).project_license == "MIT"


def test_config_rejects_out_of_range_thresholds(tmp_path: Path) -> None:
    for contents, field in [
        ("stale_months = -1\n", "stale_months"),
        ("scorecard_min = 10.1\n", "scorecard_min"),
        ("scorecard_min = nan\n", "scorecard_min"),
        ("stale_months = 20\nstale_medium_months = 10\n", "stale_medium_months"),
    ]:
        (tmp_path / ".pydepaudit.toml").write_text(contents)
        with pytest.raises(ValueError, match=field):
            load(tmp_path)


def test_config_rejects_coercible_numeric_string(tmp_path: Path) -> None:
    (tmp_path / ".pydepaudit.toml").write_text('stale_months = "12"\n')
    with pytest.raises(ValueError, match="stale_months"):
        load(tmp_path)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"stale_months": -1},
        {"scorecard_min": 11},
        {"scorecard_min": float("nan")},
        {"scorecard_min": 10**1000},
        {"denied_licenses": ("",)},
        {"denied_licenses": ("   ",)},
        {"project_license": 42},
        {"project_license": "   "},
    ],
)
def test_config_constructor_rejects_invalid_policy(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        Config(**kwargs)  # type: ignore[arg-type]
