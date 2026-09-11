"""File manager scoped to a root dir. No symlink escapes."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

MAX_FILE = 5 * 1024 * 1024


def resolve(root: str | Path, rel: str) -> Path:
    root = Path(root).resolve()
    p = (root / (rel or ".")).resolve()
    if p != root and root not in p.parents:
        raise PermissionError("escape")
    return p


def list_dir(root: str | Path, rel: str = "") -> list[dict]:
    p = resolve(root, rel)
    if not p.is_dir():
        raise NotADirectoryError(str(rel))
    out = []
    for e in sorted(p.iterdir(), key=lambda e: (e.is_file(), e.name.lower())):
        try:
            st = e.stat()
            out.append({"name": e.name, "dir": e.is_dir(),
                        "size": st.st_size, "mtime": int(st.st_mtime)})
        except OSError:
            continue
    return out


def read_text(root: str | Path, rel: str) -> str:
    p = resolve(root, rel)
    if p.stat().st_size > MAX_FILE:
        raise ValueError("too large")
    return p.read_text(errors="replace")


def write_text(root: str | Path, rel: str, content: str) -> None:
    p = resolve(root, rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def mkdir(root: str | Path, rel: str) -> None:
    resolve(root, rel).mkdir(parents=True, exist_ok=True)


def remove(root: str | Path, rel: str) -> None:
    p = resolve(root, rel)
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p)
    else:
        p.unlink()


def disk_usage(path: str | Path) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                continue
    return total
