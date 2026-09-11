"""Filesystem quotas (ext4 usrquota). Pure helpers are unit-tested;
actual setquota runs as root via runner."""
from __future__ import annotations

import re

from . import runner as R

UNIT = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4,
        "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}


def parse_size(s: str) -> int:
    """'2G'/'500M'/'100K'/bytes -> bytes. Raises ValueError."""
    s = str(s or "").strip().upper().replace(" ", "")
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([KMGT]?B?)?", s)
    if not m:
        raise ValueError(f"bad size: {s!r}")
    num, unit = m.groups()
    return int(float(num) * UNIT.get(unit or "", 1))


def quota_argv(user: str, limit: str, mount: str = "/") -> list[str]:
    """setquota argv: equal soft/hard = hard cap."""
    blocks = parse_size(limit) // 1024
    if blocks <= 0:
        raise ValueError("limit too small")
    return ["setquota", "-u", user, str(blocks), str(blocks), "0", "0", mount]


def apply_quota(user: str, limit: str | None, mount: str = "/") -> tuple[bool, str]:
    if not limit:
        return False, "no limit set"
    try:
        argv = quota_argv(user, limit, mount)
    except ValueError as e:
        return False, str(e)
    code, out = R.run_as(argv, None, timeout=30)
    return (code == 0), out.strip()[-500:] or f"exit {code}"
