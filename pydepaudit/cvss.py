"""CVSS v3.x base score calculation.

OSV entries for PyPI usually carry a GHSA severity label, but some only have a
CVSS vector string — this scores those vectors so every vulnerability maps to
a severity band.
"""

import math

_METRICS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

_PR: dict[str, dict[str, float]] = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


def base_score(vector: str) -> float | None:
    """Return the CVSS v3.x base score for *vector*, or None if invalid."""
    parts = vector.strip().split("/")
    if not parts[0].startswith("CVSS:3"):
        return None
    metrics = dict(part.split(":", 1) for part in parts[1:] if ":" in part)
    try:
        scope = metrics["S"]
        if scope not in _PR:
            return None
        av = _METRICS["AV"][metrics["AV"]]
        ac = _METRICS["AC"][metrics["AC"]]
        pr = _PR[scope][metrics["PR"]]
        ui = _METRICS["UI"][metrics["UI"]]
        c = _METRICS["C"][metrics["C"]]
        i = _METRICS["I"][metrics["I"]]
        a = _METRICS["A"][metrics["A"]]
    except KeyError:
        return None

    isc = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * isc
    else:
        impact = 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def severity_band(score: float | None) -> str:
    """Map a CVSS score to a severity label."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _roundup(value: float) -> float:
    """CVSS spec roundup: smallest 1-decimal number >= value."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000
    return (math.floor(scaled / 10000) + 1) / 10
