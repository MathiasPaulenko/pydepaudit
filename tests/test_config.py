from pathlib import Path

from pydepaudit.config import load


def test_load_defaults(tmp_path: Path) -> None:
    config = load(tmp_path)
    assert config.stale_months == 12
    assert config.stale_medium_months == 18
    assert config.denied_licenses == ("GPL", "AGPL", "SSPL")
    assert config.ignored == {}


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
