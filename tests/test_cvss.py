import pytest

from pydepaudit.cvss import base_score, severity_band
from pydepaudit.cvss4 import base_score_v4


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
    assert base_score("CVSS:30/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None
    assert base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H") is None
    assert base_score("CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:X") is None
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:Z") is None
    assert base_score(None) is None  # type: ignore[arg-type]


def test_base_score_accepts_valid_non_base_metrics() -> None:
    base = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    extended = f"{base}/E:F/RL:W/RC:C/CR:M/IR:L/AR:H/MAV:A"
    assert base_score(extended) == base_score(base)


@pytest.mark.parametrize(
    ("score", "band"),
    [(10.0, "critical"), (7.5, "high"), (5.0, "medium"), (1.0, "low"), (0.0, "none")],
)
def test_severity_band(score: float, band: str) -> None:
    assert severity_band(score) == band
    assert severity_band(None) == "unknown"


# known-answer vectors verified against the official FIRST/Red Hat calculator
@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
        (
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:H/SI:H/SA:L"
            "/CR:H/AR:H/MUI:N",
            5.3,
        ),
        (
            "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:H/VI:N/VA:H/SC:L/SI:N/SA:H"
            "/IR:M/MSA:S/MAV:L",
            8.4,
        ),
        ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:H/SI:N/SA:H/IR:H", 7.0),
    ],
)
def test_base_score_v4(vector: str, expected: float) -> None:
    assert base_score_v4(vector) == expected


def test_base_score_v4_invalid() -> None:
    assert base_score_v4("not a vector") is None
    assert base_score_v4(None) is None  # type: ignore[arg-type]
    assert base_score_v4("CVSS:3.1/AV:N") is None
    assert (
        base_score_v4("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
        is None
    )
    assert base_score_v4("CVSS:4.0/AV:N") is None


_BASE4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"


@pytest.mark.parametrize(
    "suffix",
    [
        "/MSI:Z",  # invalid modified value — must not crash nor score
        "/MSA:Q",
        "/CR:Z",
        "/E:Q",
        "/ME:P",  # nonexistent metric — must not hijack E
        "/FOO:X",
        "/AV:N",  # duplicate metric
        "/",  # trailing slash → empty field
        "/U:Bogus",  # invalid provider-urgency value
    ],
)
def test_base_score_v4_malformed_fields(suffix: str) -> None:
    assert base_score_v4(_BASE4 + suffix) is None


@pytest.mark.parametrize(
    ("suffix", "expected"),
    [
        ("/MSI:S", 10.0),  # safety-modified integrity — valid, eq4=0
        ("/MSA:S", 10.0),
        ("/U:Red", 10.0),  # supplemental metric accepted
        ("/S:P", 10.0),
    ],
)
def test_base_score_v4_optional_metrics(suffix: str, expected: float) -> None:
    assert base_score_v4(_BASE4 + suffix) == expected
