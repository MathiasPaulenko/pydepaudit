"""Local file cache for HTTP source data."""

import json
import re
import time
from pathlib import Path
from typing import Any

DEFAULT_TTL_SECONDS = 3600


class FileCache:
    """Best-effort JSON file cache with a time-to-live.

    Failures are swallowed on purpose: a broken cache must never break
    the audit.
    """

    def __init__(self, directory: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._dir = directory
        self._ttl = ttl_seconds

    def get(self, key: str) -> Any:
        """Return the cached value for *key*, or None if missing or stale."""
        file = self._file(key)
        try:
            if time.time() - file.stat().st_mtime > self._ttl:
                return None
            return json.loads(file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def set(self, key: str, value: Any) -> None:
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            self._file(key).write_text(json.dumps(value), encoding="utf-8")
        except (OSError, TypeError):
            pass

    def _file(self, key: str) -> Path:
        name = re.sub(r"[^A-Za-z0-9._-]", "_", key)
        return self._dir / f"{name}.json"
