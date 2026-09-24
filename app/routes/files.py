"""File routes. Every path is resolved through the anchored walk in
``app.safepath``; nothing here ever hands a user-controlled path string to the
OS twice."""
from __future__ import annotations

import asyncio
import os
import re
import stat
import time
import zipfile
from contextlib import suppress

from fastapi import APIRouter, Cookie, HTTPException, Request
from starlette.datastructures import UploadFile

from .. import audit as AUDIT
from .. import deps as P
from .. import files as F
from .. import security as SEC
from ..fileserv import FdFileResponse

router = APIRouter()

# Uploads are streamed in chunks so a 200 MiB file never lands in RAM at once.
CHUNK = 1024 * 1024

# Quota = a full walk of the home dir. The UI re-fetches the listing on every
# mutation, so a short cache keeps that from turning into a disk thrash.
_USAGE_TTL = 5.0
_usage_cache: dict[str, tuple[float, int]] = {}


async def _quota(u: dict, root) -> dict:
    """Used bytes under ``root`` plus the configured limit."""
    if str(root) == "/":
        from .. import metrics as _M
        d = _M.disk("/")
        return {"used": d["used"], "limit": None}
    key = str(root)
    now = time.monotonic()
    hit = _usage_cache.get(key)
    if hit and now - hit[0] < _USAGE_TTL:
        used = hit[1]
    else:
        used = await asyncio.to_thread(F.disk_usage, root)
        _usage_cache[key] = (now, used)
        if len(_usage_cache) > 64:          # bounded: oldest entry out
            _usage_cache.pop(next(iter(_usage_cache)))
    return {"used": used, "limit": (u.get("limits") or {}).get("disk_quota")}


def bust_usage_cache(root) -> None:
    """Drop a cached quota after a mutation."""
    _usage_cache.pop(str(root), None)


def _audit_files(u: dict, action: str, root, request, *, path: str = "",
                 slot: str | None = None) -> None:
    """Record the file mutations that are worth keeping, and stay quiet on the rest.

    Two signals matter here:

    * **destructive** — a ``delete`` is irreversible and the panel runs it as
      root inside someone's home, so who deleted what is exactly what an
      incident review asks for;
    * **cross-slot** — an admin reaching into a *foreign* slot. A non-admin is
      always pinned to their own home, so a non-empty ``slot`` that differs
      from the caller's own can only be an admin acting on someone else's
      files, which is how a compromised admin account plants or exfiltrates.

    Ordinary reads/writes inside your own home are routine user activity and are
    deliberately not logged — an audit trail buried in them is useless.
    """
    own = (u.get("slot") or "")
    foreign = bool(u.get("is_admin")) and bool(slot) and slot != own
    if action != "delete" and not foreign:
        return
    AUDIT.event("file_" + action, root=str(root), path=path[:512],
                target_slot=slot if foreign else None,
                ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(u))


# ---------- listing / reading ----------

@router.get("/api/files")
async def files_list(path: str = "", slot: str = "",
                     dach_sid: str | None = Cookie(default=None)):
    """Single round trip: entries + quota together (tunnel latency matters)."""
    u = await P.require("files", dach_sid)
    try:
        root = P.home_of(u, slot or None)
        entries = await asyncio.to_thread(F.list_dir, root, path)
    except (PermissionError, NotADirectoryError, OSError) as e:
        raise HTTPException(400, str(e)) from None
    return {"entries": entries, "quota": await _quota(u, root)}


@router.get("/api/files/read")
async def files_read(path: str, slot: str = "",
                     dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    try:
        root = P.home_of(u, slot or None)
        content = await asyncio.to_thread(F.read_text, root, path)
    except (PermissionError, OSError, ValueError) as e:
        raise HTTPException(400, str(e)) from None
    return {"content": content}


# ---------- mutations ----------

@router.post("/api/files/write")
async def files_write(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    slot = body.get("slot") or None
    try:
        root = P.home_of(u, slot)
        await asyncio.to_thread(F.write_text, root, body.get("path", ""),
                                body.get("content", ""))
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e)) from None
    bust_usage_cache(root)
    _audit_files(u, "write", root, request, path=str(body.get("path", "")),
                 slot=slot)
    return {"ok": True}


@router.post("/api/files/mkdir")
async def files_mkdir(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    slot = body.get("slot") or None
    try:
        root = P.home_of(u, slot)
        await asyncio.to_thread(F.mkdir, root, body.get("path", ""))
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e)) from None
    bust_usage_cache(root)
    _audit_files(u, "mkdir", root, request, path=str(body.get("path", "")),
                 slot=slot)
    return {"ok": True}


@router.post("/api/files/delete")
async def files_delete(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    slot = body.get("slot") or None
    try:
        root = P.home_of(u, slot)
        await asyncio.to_thread(F.remove, root, body.get("path", ""))
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e)) from None
    bust_usage_cache(root)
    # irreversible, and performed by root inside someone's home
    _audit_files(u, "delete", root, request, path=str(body.get("path", "")),
                 slot=slot)
    return {"ok": True}


@router.post("/api/files/move")
async def files_move(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    slot = body.get("slot") or None
    try:
        root = P.home_of(u, slot)
        await asyncio.to_thread(F.move, root, body.get("path", ""),
                                body.get("to", ""))
    except FileExistsError:
        raise HTTPException(409, "target exists") from None
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e)) from None
    bust_usage_cache(root)
    _audit_files(u, "move", root, request,
                 path=f"{body.get('path', '')} -> {body.get('to', '')}",
                 slot=slot)
    return {"ok": True}


@router.post("/api/files/copy")
async def files_copy(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    slot = body.get("slot") or None
    try:
        root = P.home_of(u, slot)
        await asyncio.to_thread(F.copy, root, body.get("path", ""),
                                body.get("to", ""))
    except FileExistsError:
        raise HTTPException(409, "target exists") from None
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e)) from None
    bust_usage_cache(root)
    _audit_files(u, "copy", root, request,
                 path=f"{body.get('path', '')} -> {body.get('to', '')}",
                 slot=slot)
    return {"ok": True}


@router.post("/api/files/upload")
async def files_upload(request: Request, path: str = "", slot: str = "",
                       dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    form = await request.form()
    max_mb = int(P.CFG.get("max_upload_mb", 200))
    max_bytes = max_mb * 1024 * 1024
    ups = form.getlist("file")
    if not ups:
        raise HTTPException(400, "no file")
    # A multipart part named "file" arrives as an UploadFile only when it was
    # sent as a file; sent as a plain field it is a str. Reject that instead of
    # dereferencing .filename on a string and answering 500 to what is a bad
    # request. (mypy flagged the union; it was a real bug, not a false alarm.)
    uploads: list[UploadFile] = []
    for item in ups:
        if isinstance(item, str):
            raise HTTPException(400, "'file' must be sent as a file part")
        uploads.append(item)
    results: list[dict[str, object]] = []
    try:
        root = P.home_of(u, slot or None)
    except (PermissionError, ValueError) as e:
        raise HTTPException(400, str(e)) from None
    for up in uploads:
        fname = re.sub(r"[\\/]+", "_", up.filename or "upload").lstrip(".")
        if not fname:
            raise HTTPException(400, "bad filename")
        rel = f"{path}/{fname}".strip("/") if path else fname
        try:
            size = await _stream_to_disk(root, rel, up, max_bytes)
        except HTTPException:
            raise
        except (PermissionError, OSError) as e:
            raise HTTPException(400, str(e)) from None
        results.append({"name": fname, "size": size})
    bust_usage_cache(root)
    for res in results:
        _audit_files(u, "upload", root, request, path=str(res["name"]),
                     slot=slot)
    # always a list, one entry per uploaded part. It used to branch on a
    # `single` flag that could never be true — `form.getlist("file")` returns
    # a one-element list for a single file too, so the scalar form was dead
    # code. The SPA only reads `r.ok`; an explicit list is the honest contract.
    return {"ok": True, "files": results}


async def _stream_to_disk(root, rel: str, up, max_bytes: int) -> int:
    """Write an upload in chunks, enforcing the cap without buffering it.

    An oversized or failed upload is aborted and its partial file removed, so a
    rejected upload cannot leave a half-written file behind.
    """
    fd = await asyncio.to_thread(F.open_write_fd, root, rel)
    total = 0
    try:
        try:
            while True:
                chunk = await up.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(
                        400, f"too large (max {max_bytes // (1024 * 1024)} MiB)")
                await asyncio.to_thread(os.write, fd, chunk)
        finally:
            await asyncio.to_thread(os.close, fd)
    except BaseException:
        await asyncio.to_thread(F.abort_write, root, rel)
        raise
    return total


@router.post("/api/files/unzip")
async def files_unzip(request: Request, dach_sid: str | None = Cookie(default=None)):
    """Deploy a zip: unpack inside the user's root (safe members only)."""
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    rel = str(body.get("path", "")).strip("/")
    into = str(body.get("into", "")).strip("/")
    slot = body.get("slot") or None
    root = P.home_of(u, slot)
    if not rel.lower().endswith(".zip"):
        raise HTTPException(400, "not a zip")
    try:
        written = await asyncio.to_thread(F.extract_zip, root, rel, into)
    except zipfile.BadZipFile:
        raise HTTPException(400, "not a valid zip") from None
    except (PermissionError, ValueError, OSError) as e:
        raise HTTPException(400, str(e)) from None
    bust_usage_cache(root)
    stem = into or rel.rsplit("/", 1)[-1].removesuffix(".zip") or "unpacked"
    # Own-home writes are routine — a slot user has a live shell there and can
    # do the same unlogged, so auditing them would be false completeness. The
    # signals that matter are the same as elsewhere: destructive ops and an
    # admin reaching across a slot boundary.
    _audit_files(u, "unzip", root, request, path=f"{rel} -> {into}", slot=slot)
    return {"ok": True, "files": len(written), "into": stem}


# ---------- delivery ----------

@router.get("/api/files/download")
async def files_download(request: Request, path: str, slot: str = "",
                         dach_sid: str | None = Cookie(default=None)):
    """Always a download, never a document.

    Slot users control the bytes and the file name, and the panel's session
    cookie rides this origin. Serving a stored ``evil.html`` with a sniffed
    ``text/html`` type would run attacker script *inside the panel origin* —
    which can read ``/api/csrf`` and mint an admin token. Forcing
    ``application/octet-stream`` plus ``Content-Disposition: attachment`` and
    ``nosniff`` makes that inert on every browser.

    The bytes are streamed from the descriptor the anchored walk opened, not
    re-opened by name: a slot user racing a symlink into the path between the
    two would otherwise hand root a file outside its home.
    """
    u = await P.require("files", dach_sid)
    try:
        root = P.home_of(u, slot or None)
        fd, st = await asyncio.to_thread(_open_file_fd, root, path)
    except (PermissionError, IsADirectoryError, OSError) as e:
        raise HTTPException(400, str(e)) from None
    name = os.path.basename(path) or "download"
    return FdFileResponse(fd, st, None, SEC.attachment_headers(name),
                          request.headers.get("range"))


@router.get("/api/files/preview")
async def files_preview(request: Request, path: str, slot: str = "",
                        dach_sid: str | None = Cookie(default=None)):
    """Inline media preview.

    Only a fixed allow-list of passive media types is ever rendered inline.
    HTML, SVG and JS are refused outright and fall back to a download, the
    declared MIME type is forced (never sniffed from the bytes), and ``nosniff``
    keeps the browser from second-guessing it.

    Streamed from the descriptor the anchored walk opened — see
    :func:`files_download` for why the name is never re-opened.
    """
    u = await P.require("files", dach_sid)
    name = os.path.basename(path) or "file"
    preview = SEC.preview_headers(name)
    if preview is None:
        raise HTTPException(
            415, "type is not previewable — download it instead")
    media, headers = preview
    try:
        root = P.home_of(u, slot or None)
        fd, st = await asyncio.to_thread(_open_file_fd, root, path)
    except (PermissionError, IsADirectoryError, OSError) as e:
        raise HTTPException(400, str(e)) from None
    return FdFileResponse(fd, st, media, headers, request.headers.get("range"))


def _open_file_fd(root, path: str) -> tuple[int, os.stat_result]:
    """(fd, stat) for ``path`` under ``root`` — opened once, through the anchor.

    The stat comes from the descriptor itself, so the size and mtime the
    response advertises describe the inode actually being streamed.
    """
    fd = F.open_read_fd(root, path)
    try:
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            raise IsADirectoryError("is a directory")
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError("not a regular file")
    except BaseException:
        with suppress(OSError):
            os.close(fd)
        raise
    return fd, st


@router.get("/api/quota")
async def quota(slot: str = "", dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    root = P.home_of(u, slot or None)
    return await _quota(u, root)
