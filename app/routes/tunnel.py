from fastapi import APIRouter, Cookie, Request
from .. import db as D
from .. import deps as P
from .. import tunnel as T
import asyncio

router = APIRouter()
# ---------- tunnel ----------

@router.get("/api/tunnel")
async def tunnel_url(request: Request, refresh: bool = False,
                     dach_sid: str | None = Cookie(default=None)):
    u = await P.require("tunnel_view", dach_sid, request)
    t = P.CFG.get("tunnel", {})
    if refresh:
        T.refresh()
    url = await asyncio.to_thread(
        T.current, t.get("provider", ""), t.get("args", []),
        int(t.get("cache_seconds", 30)), t.get("cache_file"))
    _ = u
    return {"url": url}


@router.post("/api/tunnel/refresh")
async def tunnel_refresh(request: Request, dach_sid: str | None = Cookie(default=None)):
    await P.require("tunnel_view", dach_sid, request)
    P.check_csrf(request, dach_sid)
    T.refresh()
    return {"ok": True}
