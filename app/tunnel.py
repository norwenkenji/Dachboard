"""Tunnel providers. Any executable whose stdout contains the public URL."""
from __future__ import annotations

import re
import subprocess
import time

URL_RE = re.compile(r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\"']*)?")

_cache: dict = {"url": None, "ts": 0}


def current(provider: str, args: list[str], cache_seconds: int = 30,
            cache_file: str | None = None) -> str | None:
    now = time.time()
    if _cache["url"] and now - _cache["ts"] < cache_seconds:
        return _cache["url"]
    url = _run_provider(provider, args)
    if url and cache_file:
        try:
            with open(cache_file, "w") as f:
                f.write(url)
        except OSError:
            pass
    if url:
        _cache.update(url=url, ts=now)
        return url
    if cache_file:
        try:
            with open(cache_file) as f:
                return f.read().strip() or _cache["url"]
        except OSError:
            pass
    return _cache["url"]


def refresh() -> None:
    _cache.update(url=None, ts=0)


def _run_provider(provider: str, args: list[str]) -> str | None:
    try:
        r = subprocess.run([provider, *(args or [])],
                           capture_output=True, text=True, timeout=15)
        m = URL_RE.search(r.stdout + "\n" + r.stderr)
        return m.group(0).rstrip(").,") if m else None
    except Exception:
        return None
