"""Local file cache for HTTP source data."""

import contextlib
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

DEFAULT_TTL_SECONDS = 3600


def default_cache_dir() -> Path:
    """Return a per-user cache path outside any audited project directory."""
    if os.name == "nt":
        configured = os.environ.get("LOCALAPPDATA")
        root = (
            Path(configured)
            if configured and Path(configured).is_absolute()
            else Path.home() / "AppData/Local"
        )
    elif sys.platform == "darwin":
        root = Path.home() / "Library/Caches"
    else:
        configured = os.environ.get("XDG_CACHE_HOME")
        root = (
            Path(configured)
            if configured and Path(configured).is_absolute()
            else Path.home() / ".cache"
        )
    return root / "pydepaudit"


class FileCache:
    """Best-effort JSON file cache with a time-to-live.

    Failures are swallowed on purpose: a broken cache must never break
    the audit.
    """

    def __init__(self, directory: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        try:
            valid_ttl = (
                not isinstance(ttl_seconds, bool)
                and isinstance(ttl_seconds, int | float)
                and math.isfinite(ttl_seconds)
            )
        except OverflowError:
            valid_ttl = False
        if not valid_ttl:
            raise ValueError("ttl_seconds must be a finite number")
        self._dir = directory
        self._ttl = ttl_seconds

    def get(self, key: str) -> Any:
        """Return the cached value for *key*, or None if missing or stale."""
        if not isinstance(key, str):
            return None
        file = self._file(key)
        try:
            if time.time() - file.stat().st_mtime > self._ttl:
                return None
            return json.loads(file.read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            return None

    def set(self, key: str, value: Any) -> None:
        tmp: Path | None = None
        try:
            if not isinstance(key, str):
                return
            payload = json.dumps(value, allow_nan=False)
            self._dir.mkdir(parents=True, exist_ok=True)
            # Unique temp files allow concurrent writers for the same key.
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self._dir,
                prefix=".pydepaudit-",
                suffix=".tmp",
                delete=False,
            ) as stream:
                tmp = Path(stream.name)
                stream.write(payload)
            os.replace(tmp, self._file(key))
        except (OSError, TypeError, ValueError, RecursionError):
            if tmp is not None:
                with contextlib.suppress(OSError):
                    tmp.unlink(missing_ok=True)

    def _file(self, key: str) -> Path:
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", key)[:64]
        digest = hashlib.sha256(key.encode("utf-8", errors="surrogatepass")).hexdigest()
        name = f"{slug}-{digest}"
        return self._dir / f"{name}.json"
