from fastapi import APIRouter, Cookie, Request, UploadFile
from fastapi.responses import FileResponse
from .. import db as D
from .. import deps as P
from .. import files as F
from fastapi import HTTPException
import asyncio
import re

router = APIRouter()
# ---------- files ----------

@router.get("/api/files")
async def files_list(path: str = "", slot: str = "",
                     dach_sid: str | None = Cookie(default=None)):
    """Single round trip: entries + quota together (tunnel latency matters)."""
    u = await P.require("files", dach_sid)
    try:
        root = P.home_of(u, slot or None)
        entries = F.list_dir(root, path)
    except (PermissionError, NotADirectoryError, OSError) as e:
        raise HTTPException(400, str(e))
    if str(root) == "/":
        from .. import metrics as _M
        d = _M.disk("/")
        quota = {"used": d["used"], "limit": None}
    else:
        used = await asyncio.to_thread(F.disk_usage, root)
        quota = {"used": used, "limit": (u.get("limits") or {}).get("disk_quota")}
    return {"entries": entries, "quota": quota}


@router.get("/api/files/read")
async def files_read(path: str, slot: str = "",
                     dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    try:
        return {"content": F.read_text(P.home_of(u, slot or None), path)}
    except (PermissionError, OSError, ValueError) as e:
        raise HTTPException(400, str(e))


@router.post("/api/files/write")
async def files_write(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    try:
        F.write_text(P.home_of(u, body.get("slot") or None),
                     body.get("path", ""), body.get("content", ""))
        return {"ok": True}
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))


@router.post("/api/files/mkdir")
async def files_mkdir(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    try:
        F.mkdir(P.home_of(u, body.get("slot") or None), body.get("path", ""))
        return {"ok": True}
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))


@router.post("/api/files/delete")
async def files_delete(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    try:
        F.remove(P.home_of(u, body.get("slot") or None), body.get("path", ""))
        return {"ok": True}
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))


@router.post("/api/files/move")
async def files_move(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    try:
        F.move(P.home_of(u, body.get("slot") or None),
               body.get("path", ""), body.get("to", ""))
        return {"ok": True}
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))


@router.post("/api/files/copy")
async def files_copy(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    try:
        F.copy(P.home_of(u, body.get("slot") or None),
               body.get("path", ""), body.get("to", ""))
        return {"ok": True}
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))


@router.post("/api/files/upload")
async def files_upload(request: Request, path: str = "", slot: str = "",
                       dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    form = await request.form()
    max_mb = int(P.CFG.get("max_upload_mb", 200))
    ups = form.getlist("file") or []
    single = not ups
    if single:
        up = form.get("file")
        if not up:
            raise HTTPException(400, "no file")
        ups = [up]
    results = []
    try:
        root = P.home_of(u, slot or None)
        for up in ups:
            fname = up.filename or "upload"
            fname = re.sub(r"[\\/]+", "_", fname).lstrip(".")
            if not fname:
                raise HTTPException(400, "bad filename")
            dest = F.resolve(root, (path + "/" + fname).strip("/") if path else fname)
            data = await up.read()
            if len(data) > max_mb * 1024 * 1024:
                raise HTTPException(400, f"too large (max {max_mb} MiB)")
            dest.parent.mkdir(parents=True, exist_ok=True)
            await asyncio.to_thread(dest.write_bytes, data)
            results.append({"name": fname, "size": len(data)})
    except HTTPException:
        raise
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "files": results if not single else results[0]}


@router.post("/api/files/unzip")
async def files_unzip(request: Request, dach_sid: str | None = Cookie(default=None)):
    """Deploy a zip: unpack inside the user's root (safe members only)."""
    u = await P.require("files", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    rel = str(body.get("path", "")).strip("/")
    into = str(body.get("into", "")).strip("/")
    root = P.home_of(u, body.get("slot") or None)
    try:
        zp = F.resolve(root, rel)
        if zp.suffix.lower() != ".zip":
            raise HTTPException(400, "not a zip")
        written = await asyncio.to_thread(F.extract_zip, root, zp, into)
    except HTTPException:
        raise
    except (PermissionError, ValueError, OSError) as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "files": len(written), "into": into or zp.stem}


@router.get("/api/files/download")
async def files_download(path: str, slot: str = "",
                         dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    try:
        return FileResponse(str(F.resolve(P.home_of(u, slot or None), path)))
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))


@router.get("/api/quota")
async def quota(slot: str = "", dach_sid: str | None = Cookie(default=None)):
    u = await P.require("files", dach_sid)
    root = P.home_of(u, slot or None)
    if str(root) == "/":
        from .. import metrics as _M
        d = _M.disk("/")
        return {"used": d["used"], "limit": None}
    used = await asyncio.to_thread(F.disk_usage, root)
    limit = (u.get("limits") or {}).get("disk_quota")
    return {"used": used, "limit": limit}

