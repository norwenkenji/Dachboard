import re
from contextlib import closing
from fastapi import APIRouter, Cookie, Request
from .. import db as D
from .. import deps as P
from .. import metrics as M
from .. import runner as R
from fastapi import HTTPException
import asyncio

router = APIRouter()
# ---------- metrics / overview ----------

@router.get("/api/metrics")
async def metrics_live(dach_sid: str | None = Cookie(default=None)):
    await P.require("overview", dach_sid)
    return await asyncio.to_thread(M.snapshot)


@router.get("/api/metrics/history")
async def metrics_history(dach_sid: str | None = Cookie(default=None)):
    await P.require("overview", dach_sid)
    with closing(D.connect(P.DB)) as con:
        rows = con.execute(
            "SELECT * FROM metrics ORDER BY ts DESC LIMIT 288").fetchall()
    return [dict(r) for r in reversed(rows)]


@router.get("/api/services")
async def services(dach_sid: str | None = Cookie(default=None)):
    await P.require("overview", dach_sid)
    code, out = await asyncio.to_thread(
        R.run_as, ["systemctl", "list-units", "--type=service", "--all",
                   "--no-pager", "--no-legend"], None, 15)
    units = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            units.append({"unit": parts[0], "load": parts[1],
                          "active": parts[2], "desc": " ".join(parts[4:])})
    return units


P.UNIT_RE = re.compile(r"^[A-Za-z0-9@.:_-]+\.(service|socket|timer|target)$")


@router.get("/api/services/{name}/logs")
async def service_logs(name: str, tail: int = 200,
                       dach_sid: str | None = Cookie(default=None)):
    await P.require("containers_view", dach_sid)
    if not P.UNIT_RE.match(name):
        raise HTTPException(400, "bad unit name")
    code, out = await asyncio.to_thread(
        R.run_as, ["journalctl", "-u", name, "-n", str(max(1, min(tail, 1000))),
                   "--no-pager"], None, 20)
    return {"logs": out[-100_000:]}


@router.post("/api/services/{name}/{action}")
async def service_action(name: str, action: str, request: Request,
                         dach_sid: str | None = Cookie(default=None)):
    await P.require("containers_control", dach_sid)
    P.check_csrf(request, dach_sid)
    if not P.UNIT_RE.match(name) or action not in ("start", "stop", "restart"):
        raise HTTPException(400, "bad unit or action")
    code, out = await asyncio.to_thread(
        R.run_as, ["systemctl", action, name], None, 60)
    return {"code": code, "output": out[-4000:]}


# ---------- containers ----------

@router.get("/api/containers")
async def containers_list(dach_sid: str | None = Cookie(default=None)):
    await P.require("containers_view", dach_sid)
    return await asyncio.to_thread(M.containers)


@router.get("/api/containers/{name}/logs")
async def containers_logs(name: str, tail: int = 200,
                          dach_sid: str | None = Cookie(default=None)):
    await P.require("containers_view", dach_sid)
    return {"logs": await asyncio.to_thread(M.container_logs, name, tail)}


@router.post("/api/containers/{name}/{action}")
async def containers_action(name: str, action: str, request: Request,
                            dach_sid: str | None = Cookie(default=None)):
    u = await P.require("containers_control", dach_sid)
    P.check_csrf(request, dach_sid)
    code, out = await asyncio.to_thread(M.container_action, name, action)
    return {"code": code, "output": out}

