import pytest

from pydepaudit.cvss import base_score, severity_band


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
        ("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_score(vector: str, expected: float) -> None:
    assert base_score(vector) == expected


def test_base_score_invalid() -> None:
    assert base_score("not a vector") is None
    assert base_score("CVSS:2.0/AV:N/AC:L") is None
    assert base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H") is None


@pytest.mark.parametrize(
    ("score", "band"),
    [(10.0, "critical"), (7.5, "high"), (5.0, "medium"), (1.0, "low"), (0.0, "none")],
)
def test_severity_band(score: float, band: str) -> None:
    assert severity_band(score) == band
    assert severity_band(None) == "unknown"
