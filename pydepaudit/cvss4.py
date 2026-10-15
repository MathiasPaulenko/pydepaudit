"""CVSS v4.0 base score calculation.

Python port of the official FIRST/Red Hat reference implementation
(cvss-v4-calculator, BSD-2-Clause): macrovector derivation, lookup table and
severity-distance interpolation.
"""

from decimal import ROUND_HALF_UP, Decimal
from typing import Any

# nudges values like 1.4499999999999993 past the rounding boundary, matching the
# reference implementation's EPSILON
_EPSILON = 1e-6

# --- metric severity levels (cvss_score.js) ---------------------------------

_LEVELS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

_BASE_REQUIRED = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
_BASE_VALUES: dict[str, frozenset[str]] = {
    "AV": frozenset("NALP"),
    "AC": frozenset("LH"),
    "AT": frozenset("NP"),
    "PR": frozenset("NLH"),
    "UI": frozenset("NPA"),
    "VC": frozenset("HLN"),
    "VI": frozenset("HLN"),
    "VA": frozenset("HLN"),
    "SC": frozenset("HLN"),
    "SI": frozenset("HLN"),
    "SA": frozenset("HLN"),
}

# optional metrics (threat, environmental, supplemental) with their valid values
_OPTIONAL_VALUES: dict[str, frozenset[str]] = {
    "E": frozenset("XAPU"),
    "CR": frozenset("XHML"),
    "IR": frozenset("XHML"),
    "AR": frozenset("XHML"),
    "MAV": frozenset("XNALP"),
    "MAC": frozenset("XLH"),
    "MAT": frozenset("XNP"),
    "MPR": frozenset("XNLH"),
    "MUI": frozenset("XNPA"),
    "MVC": frozenset("XHLN"),
    "MVI": frozenset("XHLN"),
    "MVA": frozenset("XHLN"),
    "MSC": frozenset("XHLN"),
    "MSI": frozenset("XSHLN"),
    "MSA": frozenset("XSHLN"),
    "S": frozenset("XNP"),
    "AU": frozenset("XNY"),
    "R": frozenset("XAUI"),
    "V": frozenset("XDC"),
    "RE": frozenset("XLMH"),
    "U": frozenset({"X", "Clear", "Green", "Amber", "Red"}),
}

# macrovector score lookup (cvss_lookup.js)
_LOOKUP: dict[str, float] = {
    "000000": 10,
    "000001": 9.9,
    "000010": 9.8,
    "000011": 9.5,
    "000020": 9.5,
    "000021": 9.2,
    "000100": 10,
    "000101": 9.6,
    "000110": 9.3,
    "000111": 8.7,
    "000120": 9.1,
    "000121": 8.1,
    "000200": 9.3,
    "000201": 9,
    "000210": 8.9,
    "000211": 8,
    "000220": 8.1,
    "000221": 6.8,
    "001000": 9.8,
    "001001": 9.5,
    "001010": 9.5,
    "001011": 9.2,
    "001020": 9,
    "001021": 8.4,
    "001100": 9.3,
    "001101": 9.2,
    "001110": 8.9,
    "001111": 8.1,
    "001120": 8.1,
    "001121": 6.5,
    "001200": 8.8,
    "001201": 8,
    "001210": 7.8,
    "001211": 7,
    "001220": 6.9,
    "001221": 4.8,
    "002001": 9.2,
    "002011": 8.2,
    "002021": 7.2,
    "002101": 7.9,
    "002111": 6.9,
    "002121": 5,
    "002201": 6.9,
    "002211": 5.5,
    "002221": 2.7,
    "010000": 9.9,
    "010001": 9.7,
    "010010": 9.5,
    "010011": 9.2,
    "010020": 9.2,
    "010021": 8.5,
    "010100": 9.5,
    "010101": 9.1,
    "010110": 9,
    "010111": 8.3,
    "010120": 8.4,
    "010121": 7.1,
    "010200": 9.2,
    "010201": 8.1,
    "010210": 8.2,
    "010211": 7.1,
    "010220": 7.2,
    "010221": 5.3,
    "011000": 9.5,
    "011001": 9.3,
    "011010": 9.2,
    "011011": 8.5,
    "011020": 8.5,
    "011021": 7.3,
    "011100": 9.2,
    "011101": 8.2,
    "011110": 8,
    "011111": 7.2,
    "011120": 7,
    "011121": 5.9,
    "011200": 8.4,
    "011201": 7,
    "011210": 7.1,
    "011211": 5.2,
    "011220": 5,
    "011221": 3,
    "012001": 8.6,
    "012011": 7.5,
    "012021": 5.2,
    "012101": 7.1,
    "012111": 5.2,
    "012121": 2.9,
    "012201": 6.3,
    "012211": 2.9,
    "012221": 1.7,
    "100000": 9.8,
    "100001": 9.5,
    "100010": 9.4,
    "100011": 8.7,
    "100020": 9.1,
    "100021": 8.1,
    "100100": 9.4,
    "100101": 8.9,
    "100110": 8.6,
    "100111": 7.4,
    "100120": 7.7,
    "100121": 6.4,
    "100200": 8.7,
    "100201": 7.5,
    "100210": 7.4,
    "100211": 6.3,
    "100220": 6.3,
    "100221": 4.9,
    "101000": 9.4,
    "101001": 8.9,
    "101010": 8.8,
    "101011": 7.7,
    "101020": 7.6,
    "101021": 6.7,
    "101100": 8.6,
    "101101": 7.6,
    "101110": 7.4,
    "101111": 5.8,
    "101120": 5.9,
    "101121": 5,
    "101200": 7.2,
    "101201": 5.7,
    "101210": 5.7,
    "101211": 5.2,
    "101220": 5.2,
    "101221": 2.5,
    "102001": 8.3,
    "102011": 7,
    "102021": 5.4,
    "102101": 6.5,
    "102111": 5.8,
    "102121": 2.6,
    "102201": 5.3,
    "102211": 2.1,
    "102221": 1.3,
    "110000": 9.5,
    "110001": 9,
    "110010": 8.8,
    "110011": 7.6,
    "110020": 7.6,
    "110021": 7,
    "110100": 9,
    "110101": 7.7,
    "110110": 7.5,
    "110111": 6.2,
    "110120": 6.1,
    "110121": 5.3,
    "110200": 7.7,
    "110201": 6.6,
    "110210": 6.8,
    "110211": 5.9,
    "110220": 5.2,
    "110221": 3,
    "111000": 8.9,
    "111001": 7.8,
    "111010": 7.6,
    "111011": 6.7,
    "111020": 6.2,
    "111021": 5.8,
    "111100": 7.4,
    "111101": 5.9,
    "111110": 5.7,
    "111111": 5.7,
    "111120": 4.7,
    "111121": 2.3,
    "111200": 6.1,
    "111201": 5.2,
    "111210": 5.7,
    "111211": 2.9,
    "111220": 2.4,
    "111221": 1.6,
    "112001": 7.1,
    "112011": 5.9,
    "112021": 3,
    "112101": 5.8,
    "112111": 2.6,
    "112121": 1.5,
    "112201": 2.3,
    "112211": 1.3,
    "112221": 0.6,
    "200000": 9.3,
    "200001": 8.7,
    "200010": 8.6,
    "200011": 7.2,
    "200020": 7.5,
    "200021": 5.8,
    "200100": 8.6,
    "200101": 7.4,
    "200110": 7.4,
    "200111": 6.1,
    "200120": 5.6,
    "200121": 3.4,
    "200200": 7,
    "200201": 5.4,
    "200210": 5.2,
    "200211": 4,
    "200220": 4,
    "200221": 2.2,
    "201000": 8.5,
    "201001": 7.5,
    "201010": 7.4,
    "201011": 5.5,
    "201020": 6.2,
    "201021": 5.1,
    "201100": 7.2,
    "201101": 5.7,
    "201110": 5.5,
    "201111": 4.1,
    "201120": 4.6,
    "201121": 1.9,
    "201200": 5.3,
    "201201": 3.6,
    "201210": 3.4,
    "201211": 1.9,
    "201220": 1.9,
    "201221": 0.8,
    "202001": 6.4,
    "202011": 5.1,
    "202021": 2,
    "202101": 4.7,
    "202111": 2.1,
    "202121": 1.1,
    "202201": 2.4,
    "202211": 0.9,
    "202221": 0.4,
    "210000": 8.8,
    "210001": 7.5,
    "210010": 7.3,
    "210011": 5.3,
    "210020": 6,
    "210021": 5,
    "210100": 7.3,
    "210101": 5.5,
    "210110": 5.9,
    "210111": 4,
    "210120": 4.1,
    "210121": 2,
    "210200": 5.4,
    "210201": 4.3,
    "210210": 4.5,
    "210211": 2.2,
    "210220": 2,
    "210221": 1.1,
    "211000": 7.5,
    "211001": 5.5,
    "211010": 5.8,
    "211011": 4.5,
    "211020": 4,
    "211021": 2.1,
    "211100": 6.1,
    "211101": 5.1,
    "211110": 4.8,
    "211111": 1.8,
    "211120": 2,
    "211121": 0.9,
    "211200": 4.6,
    "211201": 1.8,
    "211210": 1.7,
    "211211": 0.7,
    "211220": 0.8,
    "211221": 0.2,
    "212001": 5.3,
    "212011": 2.4,
    "212021": 1.4,
    "212101": 2.4,
    "212111": 1.2,
    "212121": 0.5,
    "212201": 1,
    "212211": 0.3,
    "212221": 0.1,
}

# highest-severity vector compositions per EQ level (max_composed.js)
_MAX_COMPOSED: dict[str, dict[str, Any]] = {
    "eq1": {
        "0": ["AV:N/PR:N/UI:N/"],
        "1": ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        "2": ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {
        "0": ["AC:L/AT:N/"],
        "1": ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    "eq3": {
        "0": {
            "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            "1": [
                "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
                "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/",
            ],
        },
        "1": {
            "0": [
                "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
                "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/",
            ],
            "1": [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        },
        "2": {"1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
    },
    "eq4": {
        "0": ["SC:H/SI:S/SA:S/"],
        "1": ["SC:H/SI:H/SA:H/"],
        "2": ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {
        "0": ["E:A/"],
        "1": ["E:P/"],
        "2": ["E:U/"],
    },
}

# max severity distances per EQ level (max_severity.js)
_MAX_SEVERITY: dict[str, Any] = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

_EQ_GROUPS = ("eq1", "eq2", "eq3eq6", "eq4", "eq5")


def base_score_v4(vector: str) -> float | None:
    """CVSS v4.0 base score for *vector*, or None if invalid/unscorable."""
    metrics = _parse(vector)
    if metrics is None:
        return None
    # official shortcut: no impact on either system is a 0.0
    if all(_m(metrics, name) == "N" for name in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    macro = _macro_vector(metrics)
    if macro not in _LOOKUP:
        return None
    return _interpolate(metrics, macro)


def _parse(vector: str) -> dict[str, str] | None:
    if not isinstance(vector, str):
        return None
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:4.0":
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        # strict: malformed fields, duplicates, unknown keys and bad values
        # invalidate the whole vector (matching the reference implementation)
        if not sep or not key or not value or key in metrics:
            return None
        allowed = _BASE_VALUES.get(key) or _OPTIONAL_VALUES.get(key)
        if allowed is None or value not in allowed:
            return None
        metrics[key] = value
    for required in _BASE_REQUIRED:
        if metrics.get(required) not in _BASE_VALUES[required]:
            return None
    return metrics


def _m(metrics: dict[str, str], name: str) -> str:
    """Resolve a metric value: X defaults and environmental overrides."""
    value = metrics.get(name, "X")
    if name == "E" and value == "X":
        return "A"
    if name in ("CR", "IR", "AR") and value == "X":
        return "H"
    if name in ("MSI", "MSA"):
        # X means "not overridden": fall back to the base SI/SA value
        return metrics[name[1:]] if value == "X" else value
    if name in _BASE_VALUES:
        modified = metrics.get("M" + name, "X")
        if modified != "X":
            return modified
    return value


def _macro_vector(metrics: dict[str, str]) -> str:
    av, pr, ui = _m(metrics, "AV"), _m(metrics, "PR"), _m(metrics, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = "0"
    elif av == "P" or not (av == "N" or pr == "N" or ui == "N"):
        eq1 = "2"
    else:
        eq1 = "1"

    eq2 = "0" if _m(metrics, "AC") == "L" and _m(metrics, "AT") == "N" else "1"

    if _m(metrics, "VC") == "H" and _m(metrics, "VI") == "H":
        eq3 = "0"
    elif (
        _m(metrics, "VC") == "H" or _m(metrics, "VI") == "H" or _m(metrics, "VA") == "H"
    ):
        eq3 = "1"
    else:
        eq3 = "2"

    if _m(metrics, "MSI") == "S" or _m(metrics, "MSA") == "S":
        eq4 = "0"
    elif (
        _m(metrics, "SC") == "H" or _m(metrics, "SI") == "H" or _m(metrics, "SA") == "H"
    ):
        eq4 = "1"
    else:
        eq4 = "2"

    e = _m(metrics, "E")
    eq5 = "0" if e == "A" else ("1" if e == "P" else "2")

    eq6 = (
        "0"
        if (
            (_m(metrics, "CR") == "H" and _m(metrics, "VC") == "H")
            or (_m(metrics, "IR") == "H" and _m(metrics, "VI") == "H")
            or (_m(metrics, "AR") == "H" and _m(metrics, "VA") == "H")
        )
        else "1"
    )
    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


def _value(metrics_str: str, name: str) -> str:
    """Extract NAME:<value> from a max-vector composition string."""
    marker = f"{name}:"
    start = metrics_str.index(marker) + len(marker)
    end = metrics_str.find("/", start)
    return metrics_str[start:] if end < 0 else metrics_str[start:end]


def _interpolate(metrics: dict[str, str], macro: str) -> float:
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(d) for d in macro)
    value = _LOOKUP[macro]

    # next-lower macrovector scores (None when the lower macro does not exist)
    lower: dict[str, float | None] = {
        "eq1": _LOOKUP.get(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"),
        "eq2": _LOOKUP.get(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"),
        "eq4": _LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}"),
        "eq5": _LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}"),
    }
    # eq3 and eq6 move together
    if eq3 == 0 and eq6 == 0:
        lower["eq3eq6"] = max(
            (
                s
                for s in (
                    _LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"),
                    _LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"),
                )
                if s is not None
            ),
            default=None,
        )
    elif eq3 == 1 and eq6 == 0:
        lower["eq3eq6"] = _LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
    else:
        lower["eq3eq6"] = _LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")

    # compose the highest-severity vectors of the macrovector
    eq3eq6_maxes: list[str] = _MAX_COMPOSED["eq3"][str(eq3)].get(str(eq6), [])
    max_vectors = [
        f"{a}{b}{c}{d}{e}"
        for a in _MAX_COMPOSED["eq1"][str(eq1)]
        for b in _MAX_COMPOSED["eq2"][str(eq2)]
        for c in eq3eq6_maxes
        for d in _MAX_COMPOSED["eq4"][str(eq4)]
        for e in _MAX_COMPOSED["eq5"][str(eq5)]
    ]

    # first composed max vector at least as severe as the scored vector
    distances: dict[str, float] = {}
    for max_vector in max_vectors:
        distances = {
            name: (
                _LEVELS[name][_m(metrics, name)]
                - _LEVELS[name][_value(max_vector, name)]
            )
            for name in _LEVELS
        }
        if all(d >= 0 for d in distances.values()):
            break

    current = {
        "eq1": distances["AV"] + distances["PR"] + distances["UI"],
        "eq2": distances["AC"] + distances["AT"],
        "eq3eq6": (
            distances["VC"]
            + distances["VI"]
            + distances["VA"]
            + distances["CR"]
            + distances["IR"]
            + distances["AR"]
        ),
        "eq4": distances["SC"] + distances["SI"] + distances["SA"],
        "eq5": 0.0,
    }

    step = 0.1
    depth_eq3eq6 = _MAX_SEVERITY["eq3eq6"].get(eq3, {}).get(eq6)
    depths: dict[str, float | None] = {
        "eq1": _MAX_SEVERITY["eq1"].get(eq1) * step,
        "eq2": _MAX_SEVERITY["eq2"].get(eq2) * step,
        "eq3eq6": depth_eq3eq6 * step if depth_eq3eq6 else None,
        "eq4": _MAX_SEVERITY["eq4"].get(eq4) * step,
        "eq5": step,
    }

    normalized = []
    for group in _EQ_GROUPS:
        lower_score = lower[group]
        depth = depths[group]
        if lower_score is None or not depth:
            continue
        available = value - lower_score
        if available < 0:
            continue
        proportion = current[group] / depth
        normalized.append(available * proportion)

    mean_distance = sum(normalized) / len(normalized) if normalized else 0
    value = max(0.0, min(10.0, value - mean_distance))
    # CVSS rounds half-up to one decimal; the epsilon absorbs float noise
    return float(
        Decimal(value + _EPSILON).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    )
