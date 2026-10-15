"""Environment marker evaluation shared by parsers."""

from packaging.markers import Marker, UndefinedEnvironmentName


def applies_to_env(marker: Marker | None) -> bool:
    """Whether an environment marker matches the current platform."""
    if marker is None:
        return True
    try:
        return marker.evaluate()
    except (UndefinedEnvironmentName, RecursionError):
        return True  # unevaluable marker → audit it rather than silently drop
