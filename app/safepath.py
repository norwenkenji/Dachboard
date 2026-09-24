"""Race-free filesystem access under a trusted root.

Why this module exists
----------------------
The daemon runs as root while every slot user owns a live shell inside the very
tree the daemon edits on their behalf. A two-step "resolve the path, then open
the path" is a TOCTOU window: the owner can swap a component for a symlink in
between, and root ends up reading or writing outside the home.

Kernel backend (Linux — the deployment target)
----------------------------------------------
Every operation is anchored to directory descriptors and each hop opens with
``O_NOFOLLOW``, so no path string survives long enough to be swapped. A hop
that turns out to be a symlink is expanded in userspace: its target is read
through the descriptor we already hold, then re-walked hop by hop. Absolute
targets and targets that climb above the root are refused — the same contract
as ``openat2(RESOLVE_BENEATH)``, so legitimate in-home symlinks keep working
while nothing can point root at ``/etc/shadow``. Expansion is bounded like
``ELOOP``.

Fallback backend (anything without ``dir_fd``)
----------------------------------------------
The same API, resolve-and-verify. Portable so the suite runs anywhere, but not
race-free — production must run on the kernel backend. :data:`KERNEL_CAPABLE`
reports what this platform can do; tests pin :data:`FORCE_FALLBACK` to exercise
the other path.

Entries created through here inherit the root directory's owner, so a
panel-created file stays editable from the slot's own shell.
"""
from __future__ import annotations

import errno
import os
import shutil
import stat
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)

#: Whether this platform can run the anchored (race-free) backend at all.
#: ``scandir`` takes the fd positionally, so it is checked against
#: ``supports_fd`` rather than ``supports_dir_fd``.
KERNEL_CAPABLE = bool(
    _O_NOFOLLOW
    and all(fn in os.supports_dir_fd for fn in (
        os.open, os.mkdir, os.rmdir, os.unlink, os.rename, os.stat,
        os.readlink, os.symlink))
    and os.scandir in os.supports_fd
)

#: Test hook: set True to force the portable backend on a capable platform.
FORCE_FALLBACK = False

#: Which backend is live right now.
BACKEND = "kernel" if (KERNEL_CAPABLE and not FORCE_FALLBACK) else "fallback"

MAX_FILE = 5 * 1024 * 1024
MAX_ZIP_BYTES = 200 * 1024 * 1024   # unpacked ceiling, zip-bomb guard
MAX_ZIP_FILES = 5000

DIR_MODE = 0o755
FILE_MODE = 0o644

#: Symlink expansions allowed in one walk, mirroring the kernel's ELOOP bound.
MAX_SYMLINK_HOPS = 40


def _kernel() -> bool:
    return KERNEL_CAPABLE and not FORCE_FALLBACK


# --------------------------------------------------------------------------
# path splitting (platform independent, tested on every backend)
# --------------------------------------------------------------------------

def split_rel(rel: str | Path | None) -> list[str]:
    """Normalize a user-supplied relative path into safe components.

    Rejects absolute paths and any ``..`` outright — the caller's root is the
    only thing allowed to decide where these bytes land. ``..`` handling for
    *symlink targets* is a separate concern: those are expanded against the
    anchored walk, where a climb above the root is detectable and refused.
    """
    s = "" if rel is None else os.fspath(rel)
    if _is_absolute(s):
        raise PermissionError("absolute path")
    if os.name == "nt":
        s = s.replace("\\", "/")
    parts = [p for p in s.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise PermissionError("escape")
    return parts


def _is_absolute(s: str) -> bool:
    if s.startswith(("/", "\\")):
        return True
    # windows drive letter or UNC share
    return len(s) > 1 and s[1] == ":" and s[0].isalpha()


def resolve(root: str | Path, rel: str | Path | None = "") -> Path:
    """Resolved path for ``rel`` under ``root``, containment-checked.

    Follows *relative* symlinks, refusing any that land outside ``root``;
    absolute link targets are refused outright on both backends (see
    :func:`_reject_absolute_links`). This is the validation half of the fallback
    backend and a convenience for callers that only need to display a path;
    mutating callers must use the operations below, which do not re-open a path
    string they already resolved.
    """
    base = Path(root).resolve()
    parts = split_rel(rel)
    _reject_absolute_links(base, parts)
    p = base.joinpath(*parts) if parts else base
    try:
        rp = p.resolve()
    except OSError as e:                              # pragma: no cover
        raise PermissionError(str(e)) from None
    if rp != base and base not in rp.parents:
        raise PermissionError("escape")
    return rp


def _translate(e: OSError) -> Exception:
    """Map the errno an anchored open reports onto what routes expect."""
    if e.errno in (errno.ELOOP, errno.EMLINK):
        return PermissionError("symlink")
    if e.errno == errno.ENOTDIR:
        return NotADirectoryError(str(e))
    if e.errno == errno.EISDIR:
        return IsADirectoryError(str(e))
    if e.errno == errno.EEXIST:
        return FileExistsError(str(e))
    return e


def _fallback_path(base: Path, parts: list[str]) -> Path:
    """Join already-validated components under ``base``, containment-checked.

    ``resolve()`` accepts a string and re-splits it; the operations below hold
    component lists, so they go through here instead. The check is still done
    because a component list can name a symlink whose target leaves ``base``.
    """
    p = base.joinpath(*parts) if parts else base
    _reject_absolute_links(base, parts)
    try:
        rp = p.resolve()
    except OSError as e:                              # pragma: no cover
        raise PermissionError(str(e)) from None
    if rp != base and base not in rp.parents:
        raise PermissionError("escape")
    return p


def _reject_absolute_links(base: Path, parts: list[str]) -> None:
    """Refuse absolute symlink targets — parity with the anchored walk.

    ``Path.resolve()`` follows an absolute link happily as long as it happens to
    land back inside ``base``. The anchored backend cannot do that: it implements
    the ``RESOLVE_BENEATH`` contract, where an absolute link is rejected without
    regard to where it points, because deciding "does this absolute path stay
    inside the home?" by resolving it re-opens the TOCTOU window this module
    exists to close.

    So the portable backend has to refuse it too. Without this the same tree is
    accepted on a dev box and refused in production, and a suite meant to guard
    the contract quietly guards a different one — which is how the absolute-link
    tests came to pass locally while failing on the deployment target.

    Relative targets are expanded against the directory holding the link, exactly
    as the anchored walk does, and bounded by the same hop limit.
    """
    cur = base
    pending = list(parts)
    hops = 0
    while pending:
        name = pending.pop(0)
        if name == "..":
            cur = cur.parent          # containment is checked by the caller
            continue
        nxt = cur / name
        try:
            if not nxt.is_symlink():
                cur = nxt
                continue
            target = os.readlink(nxt)
        except OSError:
            cur = nxt                 # unreadable: let the open report it
            continue
        if _is_absolute(target):
            raise PermissionError("symlink escapes root")
        hops += 1
        if hops > MAX_SYMLINK_HOPS:
            raise PermissionError("too many symlinks")
        # A relative target resolves against the link's own directory, so `cur`
        # stays put while the target's components take this link's place.
        pending = _link_parts(target) + pending


# --------------------------------------------------------------------------
# ownership inheritance
# --------------------------------------------------------------------------

def _inherit_owner(root: Path) -> tuple[int, int] | None:
    """Owner a new entry should get so the slot's shell can still edit it."""
    if not hasattr(os, "fchown"):
        return None
    try:
        st = os.stat(root)
    except OSError:
        return None
    if st.st_uid == 0 and st.st_gid == 0:
        return None                                   # nothing to inherit
    return st.st_uid, st.st_gid


def _fchown(fd: int, owner: tuple[int, int] | None) -> None:
    if not owner or not hasattr(os, "fchown"):
        return
    with suppress(OSError):                             # not root / unsupported
        os.fchown(fd, owner[0], owner[1])


def _chown_l(parent_fd: int, name: str,
             owner: tuple[int, int] | None) -> None:
    """chown an entry without following a symlink (lchown semantics).

    ``os.open`` with O_NOFOLLOW refuses symlinks, so a link has to go through
    ``os.chown(dir_fd=..., follow_symlinks=False)`` instead.
    """
    if not owner or not hasattr(os, "chown"):
        return
    with suppress(OSError, NotImplementedError):
        os.chown(name, owner[0], owner[1], dir_fd=parent_fd,
                 follow_symlinks=False)


def _chown_path(p: Path, owner: tuple[int, int] | None) -> None:
    if not owner or not hasattr(os, "chown"):
        return
    with suppress(OSError, NotImplementedError, ValueError):
        os.chown(p, owner[0], owner[1], follow_symlinks=False)


def _chown_tree(p: Path, owner: tuple[int, int] | None) -> None:
    """Fallback-backend owner fixup for a whole copied subtree."""
    if not owner or not hasattr(os, "chown"):
        return
    _chown_path(p, owner)
    if not p.is_dir() or p.is_symlink():
        return
    for dirpath, dirnames, filenames in os.walk(p, followlinks=False):
        base = Path(dirpath)
        for name in [*dirnames, *filenames]:
            _chown_path(base / name, owner)


# --------------------------------------------------------------------------
# the anchored walk (kernel backend)
# --------------------------------------------------------------------------

def _walk(base: Path, parts: list[str], leaf_flags: int | None,
          leaf_mode: int) -> tuple[list[int], int, str | None]:
    """Descend to ``parts`` below ``base``, expanding symlinks on the way.

    Returns ``(held_fds, fd, leaf_name)``. The caller owns every descriptor in
    ``held_fds`` and must close them all; ``fd`` is always one of them.

    * ``leaf_flags is None`` — ``fd`` is the *parent* directory and
      ``leaf_name`` is the final component (for mkdir/unlink/rename/stat).
    * ``leaf_flags`` given — ``fd`` is the opened entry itself and
      ``leaf_name`` is ``None``.

    Symlinks are expanded in userspace: the target is read through the
    descriptor already held, then re-walked. Absolute targets and ``..`` at the
    root raise ``PermissionError`` — the same contract as
    ``openat2(RESOLVE_BENEATH)``, which keeps legitimate in-home symlinks
    working while nothing can point root outside the tree.
    """
    root_fd = os.open(str(base), os.O_RDONLY | _O_DIRECTORY)
    stack = [root_fd]                 # directory fds from the root downwards
    rest = list(parts)
    hops = 0
    try:
        while rest:
            name = rest.pop(0)
            cur = stack[-1]
            if name == "..":
                # RESOLVE_BENEATH: climbing out of the root is EXDEV, not a
                # silent clamp to the root.
                if len(stack) == 1:
                    raise PermissionError("escape")
                os.close(stack.pop())
                continue
            is_leaf = not rest
            if is_leaf and leaf_flags is None:
                return stack, cur, name
            # mypy: leaf_flags is not None whenever is_leaf (guarded above)
            flags = ((leaf_flags or 0) | _O_NOFOLLOW | _O_BINARY) if is_leaf \
                else (os.O_RDONLY | _O_NOFOLLOW | _O_BINARY | _O_DIRECTORY)
            # O_NOFOLLOW reports a symlink as ELOOP, but Linux answers ENOTDIR
            # instead when O_DIRECTORY is also set — which is exactly the
            # mid-path case. Treating that as a hard error would refuse every
            # ordinary in-home directory symlink, so a non-leaf hop accepts both
            # as "this is a link, expand it" and lets readlink decide. A real
            # ENOTDIR (a file used as a directory) surfaces as EINVAL from
            # readlink below and is re-reported unchanged.
            link_errnos: tuple[int, ...]
            if is_leaf:
                link_errnos = (errno.ELOOP, errno.EMLINK)
            else:
                link_errnos = (errno.ELOOP, errno.EMLINK, errno.ENOTDIR)
            try:
                fd = os.open(name, flags, leaf_mode, dir_fd=cur)
            except OSError as e:
                if e.errno not in link_errnos:
                    raise _translate(e) from None
                # This hop is a symlink: read the target through the fd we
                # already hold (so the swap window is closed), then walk it.
                hops += 1
                if hops > MAX_SYMLINK_HOPS:
                    raise PermissionError("too many symlinks") from None
                try:
                    target = os.readlink(name, dir_fd=cur)
                except OSError as e2:
                    if e2.errno == errno.EINVAL:
                        # Not a link: ENOTDIR really did mean a path component
                        # is a file ("notes.txt/sub"). Report the open failure,
                        # not the readlink one.
                        raise _translate(e) from None
                    raise _translate(e2) from None
                if _is_absolute(target):
                    raise PermissionError("symlink escapes root") from None
                rest = _link_parts(target) + rest
                continue
            stack.append(fd)
        if leaf_flags is None:
            # parts was empty, or resolved to a directory above the root
            raise PermissionError("root has no parent")
        return stack, stack[-1], None
    except BaseException:
        for fd in stack:
            with suppress(OSError):
                os.close(fd)
        raise


@contextmanager
def _anchor(base: Path, parts: list[str],
            leaf_flags: int | None = None,
            leaf_mode: int = FILE_MODE) -> Iterator[tuple[int, str | None]]:
    """Context-managed :func:`_walk` — closes every descriptor on the way out."""
    held, fd, leaf = _walk(base, parts, leaf_flags, leaf_mode)
    try:
        yield fd, leaf
    finally:
        for h in held:
            with suppress(OSError):
                os.close(h)


def _link_parts(target: str) -> list[str]:
    """Components of a symlink target, keeping ``..`` so the walk can police it.

    Interior ``a/..`` pairs are left alone: the walk resolves them against the
    real directory stack, which is what makes the escape check sound.
    """
    if os.name == "nt":
        target = target.replace("\\", "/")
    return [p for p in target.split("/") if p not in ("", ".")]


@contextmanager
def _parent_at(base: Path,
               parts: list[str]) -> Iterator[tuple[int, str]]:
    """(parent_fd, leaf_name) for the entry at ``parts`` below ``base``."""
    if not parts:
        raise PermissionError("root has no parent")
    with _anchor(base, parts, None) as (fd, leaf):
        assert leaf is not None
        yield fd, leaf


def _open_leaf(base: Path, parts: list[str], flags: int,
               mode: int = FILE_MODE) -> int:
    """Open the entry at ``parts`` and hand the caller its fd.

    Every intermediate descriptor is closed before returning: a live fd stays
    valid after its parent's fd is closed, so this leaks nothing and cannot
    return a descriptor the walk is about to close.
    """
    held, fd, _leaf = _walk(base, parts, flags, mode)
    for h in held:
        if h != fd:
            with suppress(OSError):
                os.close(h)
    return fd


def _entries(dfd: int) -> list[tuple[str, bool, bool]]:
    """(name, is_dir, is_symlink) for every entry, without following links."""
    out: list[tuple[str, bool, bool]] = []
    with os.scandir(dfd) as it:
        for e in it:
            try:
                out.append((e.name,
                            e.is_dir(follow_symlinks=False),
                            e.is_symlink()))
            except OSError:
                continue
    return out


def _copy_fd(src_fd: int, dst_fd: int) -> None:
    with os.fdopen(os.dup(src_fd), "rb") as sf, \
            os.fdopen(os.dup(dst_fd), "wb") as df:
        shutil.copyfileobj(sf, df, 1024 * 1024)


def _rmtree_fd(dfd: int) -> None:
    """Delete everything under ``dfd``; the caller removes ``dfd`` itself."""
    for name, is_dir, _link in _entries(dfd):
        if is_dir:
            child = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_DIRECTORY,
                            dir_fd=dfd)
            try:
                _rmtree_fd(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=dfd)
        else:
            # unlink never follows a symlink: a link swapped in between the
            # scan and here dies as a link and never takes its target
            os.unlink(name, dir_fd=dfd)


def _usage_fd(dfd: int) -> int:
    total = 0
    for name, is_dir, is_link in _entries(dfd):
        if is_link:
            continue                                  # never follow out
        if is_dir:
            child = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_DIRECTORY,
                            dir_fd=dfd)
            try:
                total += _usage_fd(child)
            finally:
                os.close(child)
        else:
            try:
                total += os.stat(name, dir_fd=dfd,
                                 follow_symlinks=False).st_size
            except OSError:
                continue
    return total


def _mkdir_at(parent_fd: int, name: str,
              owner: tuple[int, int] | None) -> None:
    try:
        os.mkdir(name, DIR_MODE, dir_fd=parent_fd)
    except FileExistsError:
        return
    except OSError as e:
        raise _translate(e) from None
    fd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_DIRECTORY,
                 dir_fd=parent_fd)
    try:
        _fchown(fd, owner)
    finally:
        os.close(fd)


def _mkdirs(base: Path, parts: list[str]) -> None:
    """Create every component of ``parts`` below ``base``.

    Each level is reached through the anchored walk, so an in-home symlink to a
    directory is followed exactly like the kernel would — and one pointing
    outside is refused instead of silently creating dirs in the wrong place.
    """
    if not parts:
        return
    owner = _inherit_owner(base)
    for i in range(1, len(parts) + 1):
        with _parent_at(base, parts[:i]) as (pfd, leaf):
            _mkdir_at(pfd, leaf, owner)


def _copytree_fd(src_fd: int, dst_fd: int,
                 owner: tuple[int, int] | None) -> None:
    for name, is_dir, is_link in _entries(src_fd):
        if is_link:
            # Recreate the link, never read through it: following would let a
            # slot drag root-owned files into its home.
            try:
                target = os.readlink(name, dir_fd=src_fd)
                os.symlink(target, name, dir_fd=dst_fd)
            except OSError:
                continue
            _chown_l(dst_fd, name, owner)
        elif is_dir:
            _mkdir_at(dst_fd, name, owner)
            sc = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_DIRECTORY,
                         dir_fd=src_fd)
            dc = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_DIRECTORY,
                         dir_fd=dst_fd)
            try:
                _copytree_fd(sc, dc, owner)
            finally:
                os.close(sc)
                os.close(dc)
        else:
            try:
                sf = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY,
                             dir_fd=src_fd)
            except OSError:
                continue
            try:
                df = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | _O_NOFOLLOW | _O_BINARY, FILE_MODE,
                             dir_fd=dst_fd)
            except OSError:
                os.close(sf)
                continue
            try:
                _copy_fd(sf, df)
                _fchown(df, owner)
            finally:
                os.close(sf)
                os.close(df)


# --------------------------------------------------------------------------
# public operations — identical contract on both backends
# --------------------------------------------------------------------------

def _open_read_parts(base: Path, parts: list[str]) -> int:
    """fd for reading ``parts``. The caller owns it."""
    if not parts:
        raise IsADirectoryError("root is a directory")
    if _kernel():
        return _open_leaf(base, parts, os.O_RDONLY)
    p = _fallback_path(base, parts)
    if p.is_dir():
        raise IsADirectoryError("/".join(parts))
    return os.open(str(p), os.O_RDONLY | _O_BINARY)


def open_read_fd(root: str | Path, rel: str | Path) -> int:
    """fd for reading ``rel``. The caller owns it.

    Symlinks that stay inside ``root`` are followed; anything pointing outside
    is refused.
    """
    return _open_read_parts(Path(root).resolve(), split_rel(rel))


def open_write_fd(root: str | Path, rel: str | Path) -> int:
    """fd for writing ``rel``, creating parent directories. Caller owns it.

    Streaming uploads need this: it lets the route write chunk by chunk without
    ever holding the whole file in memory, while keeping the anchor guarantees.
    """
    base = Path(root).resolve()
    parts = split_rel(rel)
    if not parts:
        raise PermissionError("cannot write the root itself")
    if _kernel():
        owner = _inherit_owner(base)
        if len(parts) > 1:
            _mkdirs(base, parts[:-1])
        fd = _open_leaf(base, parts,
                        os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
        _fchown(fd, owner)
        return fd
    p = _fallback_path(base, parts)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_BINARY,
                 FILE_MODE)
    _chown_path(p, _inherit_owner(base))
    return fd


def abort_write(root: str | Path, rel: str | Path) -> None:
    """Remove a partially written file after a failed upload. Best effort."""
    with suppress(OSError, PermissionError, IsADirectoryError):
        remove(root, rel)


def stat_file(root: str | Path, rel: str | Path) -> os.stat_result:
    """stat of ``rel`` as reached through the anchored walk."""
    base = Path(root).resolve()
    parts = split_rel(rel)
    if _kernel():
        with _parent_at(base, parts) as (pfd, leaf):
            try:
                return os.stat(leaf, dir_fd=pfd, follow_symlinks=False)
            except OSError as e:
                raise _translate(e) from None
    return _fallback_path(base, parts).lstat()


def list_dir(root: str | Path, rel: str | Path = "") -> list[dict]:
    base = Path(root).resolve()
    parts = split_rel(rel)
    out: list[dict] = []
    if _kernel():
        with _anchor(base, parts, os.O_RDONLY | _O_DIRECTORY) as (dfd, _l):
            out = _scan(dfd)
    else:
        p = _fallback_path(base, parts)
        if not p.is_dir():
            raise NotADirectoryError(str(rel))
        for e in p.iterdir():
            try:
                st = e.lstat()
            except OSError:
                continue
            out.append({"name": e.name, "dir": stat.S_ISDIR(st.st_mode),
                        "size": st.st_size, "mtime": int(st.st_mtime)})
    # dirs first, then case-insensitive name — same order on both backends
    out.sort(key=lambda r: (not r["dir"], r["name"].lower()))
    return out


def _scan(dfd: int) -> list[dict]:
    rows: list[dict] = []
    for name, is_dir, _link in _entries(dfd):
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except OSError:
            continue
        rows.append({"name": name, "dir": is_dir, "size": st.st_size,
                     "mtime": int(st.st_mtime)})
    return rows


def read_text(root: str | Path, rel: str | Path) -> str:
    fd = open_read_fd(root, rel)
    try:
        if os.fstat(fd).st_size > MAX_FILE:
            raise ValueError("too large")
        with os.fdopen(fd, "rb") as f:
            fd = -1                                   # f owns the fd now
            return f.read().decode("utf-8", errors="replace")
    finally:
        if fd >= 0:
            os.close(fd)


def _write_parts(base: Path, parts: list[str], data: bytes,
                 create_parents: bool = True) -> None:
    """``write_bytes`` with pre-validated components."""
    if not parts:
        raise PermissionError("cannot write the root itself")
    if _kernel():
        owner = _inherit_owner(base)
        if create_parents and len(parts) > 1:
            _mkdirs(base, parts[:-1])
        # _open_leaf closes every intermediate fd and hands over the leaf, so
        # fdopen owns it outright and no descriptor is ever closed twice.
        fd = _open_leaf(base, parts,
                        os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
        try:
            # chown through the fd we hold: a second walk would reopen the path
            # by name and hand the slot user a swap window.
            _fchown(fd, owner)
            with os.fdopen(fd, "wb") as f:
                fd = -1
                f.write(data)
        finally:
            if fd >= 0:
                os.close(fd)
        return
    p = _fallback_path(base, parts)
    if create_parents:
        p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    _chown_path(p, _inherit_owner(base))


def write_bytes(root: str | Path, rel: str | Path, data: bytes,
                create_parents: bool = True) -> None:
    _write_parts(Path(root).resolve(), split_rel(rel), data, create_parents)


def write_text(root: str | Path, rel: str | Path, content: str) -> None:
    write_bytes(root, rel, content.encode("utf-8"))


def _mkdir_parts(base: Path, parts: list[str]) -> None:
    """``mkdir`` with pre-validated components."""
    if not parts:
        return
    if _kernel():
        _mkdirs(base, parts)
        return
    owner = _inherit_owner(base)
    p = base.joinpath(*parts)
    p.mkdir(parents=True, exist_ok=True)
    for parent in [p, *p.parents]:
        if parent == base:
            break
        _chown_path(parent, owner)


def mkdir(root: str | Path, rel: str | Path) -> None:
    _mkdir_parts(Path(root).resolve(), split_rel(rel))


def remove(root: str | Path, rel: str | Path) -> None:
    """Delete ``rel`` (file, symlink, or whole subtree). Refuses the root."""
    base = Path(root).resolve()
    parts = split_rel(rel)
    if not parts:
        raise PermissionError("no root delete")
    if _kernel():
        with _parent_at(base, parts) as (pfd, leaf):
            try:
                st = os.stat(leaf, dir_fd=pfd, follow_symlinks=False)
            except OSError as e:
                raise _translate(e) from None
            if stat.S_ISDIR(st.st_mode):
                fd = os.open(leaf, os.O_RDONLY | _O_NOFOLLOW | _O_DIRECTORY,
                             dir_fd=pfd)
                try:
                    _rmtree_fd(fd)
                finally:
                    os.close(fd)
                os.rmdir(leaf, dir_fd=pfd)
            else:
                os.unlink(leaf, dir_fd=pfd)
        return
    p = resolve(base, rel)
    if p == base:
        raise PermissionError("no root delete")
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p)
    else:
        p.unlink()


def rename(root: str | Path, src: str | Path, dst: str | Path) -> None:
    base = Path(root).resolve()
    s_parts, d_parts = split_rel(src), split_rel(dst)
    if not s_parts or not d_parts:
        raise PermissionError("no root move")
    if _kernel():
        owner = _inherit_owner(base)
        if len(d_parts) > 1:
            _mkdirs(base, d_parts[:-1])
        with _parent_at(base, s_parts) as (spd, sleaf), \
                _parent_at(base, d_parts) as (dpd, dleaf):
            try:
                os.stat(dleaf, dir_fd=dpd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as e:
                raise _translate(e) from None
            else:
                raise FileExistsError(str(dst))
            try:
                os.rename(sleaf, dleaf, src_dir_fd=spd, dst_dir_fd=dpd)
            except OSError as e:
                raise _translate(e) from None
            _chown_l(dpd, dleaf, owner)
        return
    s, d = resolve(base, src), resolve(base, dst)
    if s == base or d == base:
        raise PermissionError("no root move")
    if d.exists():
        raise FileExistsError(str(dst))
    d.parent.mkdir(parents=True, exist_ok=True)
    os.rename(s, d)


def copy(root: str | Path, src: str | Path, dst: str | Path) -> None:
    base = Path(root).resolve()
    s_parts, d_parts = split_rel(src), split_rel(dst)
    if not s_parts or not d_parts:
        raise PermissionError("no root copy")
    if _kernel():
        owner = _inherit_owner(base)
        if len(d_parts) > 1:
            _mkdirs(base, d_parts[:-1])
        with _parent_at(base, d_parts) as (dpd, dleaf), \
                _parent_at(base, s_parts) as (spd, sleaf):
            try:
                os.stat(dleaf, dir_fd=dpd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as e:
                raise _translate(e) from None
            else:
                raise FileExistsError(str(dst))
            try:
                sst = os.stat(sleaf, dir_fd=spd, follow_symlinks=False)
            except OSError as e:
                raise _translate(e) from None
            if stat.S_ISLNK(sst.st_mode):
                # Recreate the link, never read through it: following would
                # let a slot drag root-owned files into its home.
                try:
                    target = os.readlink(sleaf, dir_fd=spd)
                    os.symlink(target, dleaf, dir_fd=dpd)
                except OSError as e:
                    raise _translate(e) from None
                _chown_l(dpd, dleaf, owner)
                return
            sfd = os.open(sleaf, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY,
                          dir_fd=spd)
            try:
                if stat.S_ISDIR(sst.st_mode):
                    _mkdir_at(dpd, dleaf, owner)
                    dfd = os.open(dleaf,
                                  os.O_RDONLY | _O_NOFOLLOW | _O_DIRECTORY,
                                  dir_fd=dpd)
                    try:
                        _copytree_fd(sfd, dfd, owner)
                    finally:
                        os.close(dfd)
                else:
                    dfd = os.open(dleaf, os.O_WRONLY | os.O_CREAT
                                  | os.O_EXCL | _O_NOFOLLOW | _O_BINARY,
                                  FILE_MODE, dir_fd=dpd)
                    try:
                        _copy_fd(sfd, dfd)
                        _fchown(dfd, owner)
                    finally:
                        os.close(dfd)
            finally:
                os.close(sfd)
        return
    owner = _inherit_owner(base)
    s, d = resolve(base, src), resolve(base, dst)
    if s == base or d == base:
        raise PermissionError("no root copy")
    if d.exists():
        raise FileExistsError(str(dst))
    d.parent.mkdir(parents=True, exist_ok=True)
    if s.is_symlink():
        os.symlink(os.readlink(s), d)
    elif s.is_dir():
        shutil.copytree(s, d, symlinks=True)
    else:
        shutil.copy2(s, d)
    _chown_tree(d, owner)


def disk_usage(root: str | Path) -> int:
    """Total size of regular files under ``root``. Never follows symlinks."""
    base = Path(root).resolve()
    if _kernel():
        fd = os.open(str(base), os.O_RDONLY | _O_DIRECTORY)
        try:
            return _usage_fd(fd)
        finally:
            os.close(fd)
    total = 0
    for dirpath, _dirs, files in os.walk(base, followlinks=False):
        for f in files:
            p = os.path.join(dirpath, f)
            try:
                if os.path.islink(p):
                    continue
                total += os.path.getsize(p)
            except OSError:
                continue
    return total


# --------------------------------------------------------------------------
# zip extraction (whole archive validated before the first byte is written)
# --------------------------------------------------------------------------

def _safe_member(dest: list[str], name: str) -> list[str]:
    """Archive member name -> components under ``dest``, or raise."""
    if name.startswith(("/", "\\")):
        raise PermissionError(f"absolute member: {name}")
    if ":" in name.split("/")[0]:
        raise PermissionError(f"absolute member: {name}")
    parts = [p for p in name.replace("\\", "/").split("/")
             if p not in ("", ".")]
    if ".." in parts:
        raise PermissionError(f"escaping member: {name}")
    return dest + parts


def _archive_parts(base: Path, zip_path: str | Path) -> list[str]:
    """Components of the archive below ``base``.

    Callers historically pass an already-resolved absolute path; a relative one
    is accepted too. Either way the result is a component list below the
    trusted root, so nothing outside it can ever be named.
    """
    p = Path(zip_path)
    if not p.is_absolute():
        return split_rel(p)
    rp = p.resolve()
    if rp != base and base not in rp.parents:
        raise PermissionError("escape")
    return list(rp.relative_to(base).parts)


def extract_zip(root: str | Path, zip_path: str | Path,
                into: str | Path = "") -> list[str]:
    """Unpack ``zip_path`` (itself inside ``root``) into ``into``.

    ``into`` defaults to a folder named after the archive, next to it.
    Symlink members, ``..`` members and absolute members abort the whole
    operation before anything is written.
    """
    base = Path(root).resolve()
    zp_parts = _archive_parts(base, zip_path)
    if not zp_parts:
        raise PermissionError("zip path required")
    into_parts = split_rel(into) if str(into).strip("/") else []
    dest = into_parts or [*zp_parts[:-1],
                          Path(zp_parts[-1]).stem or "unpacked"]

    zfd = _open_read_parts(base, zp_parts)
    written: list[str] = []
    try:
        with os.fdopen(zfd, "rb") as fh:
            zfd = -1
            with zipfile.ZipFile(fh) as z:
                infos = z.infolist()
                if len(infos) > MAX_ZIP_FILES:
                    raise ValueError(f"too many entries: {len(infos)}")
                total = sum(i.file_size for i in infos)
                if total > MAX_ZIP_BYTES:
                    raise ValueError(f"unpacked too large: {total} bytes")
                plan: list[tuple[zipfile.ZipInfo, list[str]]] = []
                for i in infos:
                    if i.is_dir():
                        continue
                    if (i.external_attr >> 16) & 0o170000 == 0o120000:
                        raise PermissionError(
                            f"symlink member: {i.filename}")
                    plan.append((i, _safe_member(dest, i.filename)))
                for i, parts in plan:
                    _mkdir_parts(base, parts[:-1])
                    _write_parts(base, parts, z.read(i))
                    written.append(i.filename)
    finally:
        if zfd >= 0:
            os.close(zfd)
    return written
