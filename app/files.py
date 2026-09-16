"""File manager scoped to a root dir. No symlink escapes."""
from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path

MAX_FILE = 5 * 1024 * 1024
MAX_ZIP_BYTES = 200 * 1024 * 1024   # unpacked ceiling, zip-bomb guard
MAX_ZIP_FILES = 5000


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
    if p == Path(root).resolve():
        raise PermissionError("no root delete")
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p)
    else:
        p.unlink()


def move(root: str | Path, src: str, dst: str) -> None:
    root = Path(root).resolve()
    s, d = resolve(root, src), resolve(root, dst)
    if s == root or d == root:
        raise PermissionError("no root move")
    if d.exists():
        raise FileExistsError(str(dst))
    d.parent.mkdir(parents=True, exist_ok=True)
    os.rename(s, d)


def copy(root: str | Path, src: str, dst: str) -> None:
    root = Path(root).resolve()
    s, d = resolve(root, src), resolve(root, dst)
    if s == root or d == root:
        raise PermissionError("no root copy")
    if d.exists():
        raise FileExistsError(str(dst))
    d.parent.mkdir(parents=True, exist_ok=True)
    if s.is_dir() and not s.is_symlink():
        shutil.copytree(s, d)
    else:
        shutil.copy2(s, d)


def disk_usage(path: str | Path) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                continue
    return total


def _safe_join(root: Path, name: str) -> Path:
    """Resolve an archive member name under root. Rejects traversal and links."""
    if name.startswith(("/", "\\")) or ":" in name.split("/")[0]:
        raise PermissionError(f"absolute member: {name}")
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if ".." in parts:
        raise PermissionError(f"escaping member: {name}")
    p = (root / "/".join(parts)).resolve()
    if p != root.resolve() and root.resolve() not in p.parents:
        raise PermissionError(f"escape: {name}")
    return p


def extract_zip(root: str | Path, zip_path: str | Path, into: str = "") -> list[str]:
    """Unpack a zip inside root, into `into` (defaults to the zip's own folder
    named after the archive). Returns written member names. Raises on any
    unsafe member — nothing is written in that case (validated first)."""
    root = Path(root).resolve()
    zp = Path(zip_path)
    if into:
        dest = _safe_join(root, into)
    else:
        # default: a folder named after the archive, next to it
        dest = zp.parent / (zp.stem or "unpacked")
        dest = _safe_join(root, str(dest.relative_to(root)))
    with zipfile.ZipFile(zp) as z:
        infos = z.infolist()
        if len(infos) > MAX_ZIP_FILES:
            raise ValueError(f"too many entries: {len(infos)}")
        total = sum(i.file_size for i in infos)
        if total > MAX_ZIP_BYTES:
            raise ValueError(f"unpacked too large: {total} bytes")
        targets = []
        for i in infos:
            if i.is_dir():
                targets.append((i, None))
                continue
            mode = (i.external_attr >> 16) & 0o170000
            if mode == 0o120000:  # symlink inside archive
                raise PermissionError(f"symlink member: {i.filename}")
            targets.append((i, _safe_join(dest or root, i.filename)))
        written = []
        for i, p in targets:
            if p is None:
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            with z.open(i) as src, open(p, "wb") as out:
                shutil.copyfileobj(src, out, 1024 * 1024)
            written.append(i.filename)
    return written
