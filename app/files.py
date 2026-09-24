"""File manager scoped to a root dir. No symlink escapes, no TOCTOU races.

Thin facade over :mod:`app.safepath`, which holds the anchored-descriptor walk.
Kept as a module so routes and tests keep importing ``app.files``.
"""
from __future__ import annotations

from pathlib import Path

from . import safepath as SP

MAX_FILE = SP.MAX_FILE
MAX_ZIP_BYTES = SP.MAX_ZIP_BYTES
MAX_ZIP_FILES = SP.MAX_ZIP_FILES

#: Which safepath backend is live ("kernel" = race-free, "fallback" = portable).
BACKEND = SP.BACKEND


def resolve(root: str | Path, rel: str) -> Path:
    return SP.resolve(root, rel)


def list_dir(root: str | Path, rel: str = "") -> list[dict]:
    return SP.list_dir(root, rel)


def read_text(root: str | Path, rel: str) -> str:
    return SP.read_text(root, rel)


def write_text(root: str | Path, rel: str, content: str) -> None:
    SP.write_text(root, rel, content)


def mkdir(root: str | Path, rel: str) -> None:
    SP.mkdir(root, rel)


def remove(root: str | Path, rel: str) -> None:
    SP.remove(root, rel)


def move(root: str | Path, src: str, dst: str) -> None:
    SP.rename(root, src, dst)


def copy(root: str | Path, src: str, dst: str) -> None:
    SP.copy(root, src, dst)


def disk_usage(path: str | Path) -> int:
    return SP.disk_usage(path)


def extract_zip(root: str | Path, zip_path: str | Path,
                into: str = "") -> list[str]:
    return SP.extract_zip(root, zip_path, into)


def open_read_fd(root: str | Path, rel: str) -> int:
    """fd for a race-free read of ``rel``. Caller owns the descriptor."""
    return SP.open_read_fd(root, rel)


def open_write_fd(root: str | Path, rel: str) -> int:
    """fd for a race-free write of ``rel`` (parents created). Caller owns it."""
    return SP.open_write_fd(root, rel)


def abort_write(root: str | Path, rel: str) -> None:
    """Best-effort removal of a partial file after a failed upload."""
    SP.abort_write(root, rel)
