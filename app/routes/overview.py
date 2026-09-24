import asyncio
import re
from contextlib import closing

from fastapi import APIRouter, Cookie, HTTPException, Request

from .. import audit as AUDIT
from .. import db as D
from .. import deps as P
from .. import metrics as M
from .. import runner as R
from .. import security as SEC

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
    """Host-wide systemd view: an admin-only surface, see rbac.ADMIN_ONLY."""
    await P.require("services_view", dach_sid)
    _code, out = await asyncio.to_thread(
        R.run_as, ["systemctl", "list-units", "--type=service", "--all",
                   "--no-pager", "--no-legend"], None, 15)
    units = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            units.append({"unit": parts[0], "load": parts[1],
                          "active": parts[2], "desc": " ".join(parts[4:])})
    return units


@router.get("/api/services/{name}/logs")
async def service_logs(name: str, tail: int = 200,
                       dach_sid: str | None = Cookie(default=None)):
    """Journal of an arbitrary unit, read as root — admin only.

    ``journalctl -u dachboard`` alone would leak the one-time setup token that
    deps.py logs, and any application's journal can carry its secrets.
    """
    u = await P.require("services_view", dach_sid)
    if not P.UNIT_RE.fullmatch(name):
        raise HTTPException(400, "bad unit name")
    n = max(1, min(tail, 1000))
    _code, out = await asyncio.to_thread(
        R.run_as, ["journalctl", "-u", name, "-n", str(n), "--no-pager"],
        None, 20)
    # Reading a journal is a read of host secrets, so it is recorded — who
    # looked at which unit is exactly what an incident review asks for.
    AUDIT.event("service_logs", unit=name, tail=n, **AUDIT.actor(u))
    return {"logs": out[-100_000:]}


@router.post("/api/services/{name}/{action}")
async def service_action(name: str, action: str, request: Request,
                         dach_sid: str | None = Cookie(default=None)):
    """``systemctl`` on any host unit, executed as the daemon user (root).

    Stopping sshd or dachboard itself is one call away from here, so this is
    gated on services_control — admin-only — and never on containers_control.
    """
    u = await P.require("services_control", dach_sid)
    P.check_csrf(request, dach_sid)
    if not P.UNIT_RE.fullmatch(name) or action not in ("start", "stop", "restart"):
        raise HTTPException(400, "bad unit or action")
    ip = SEC.client_ip(request, P.CFG)
    code, out = await asyncio.to_thread(
        R.run_as, ["systemctl", action, name], None, 60)
    AUDIT.event("service_action", unit=name, action=action, exit=code, ip=ip,
                **AUDIT.actor(u))
    if code != 0:
        # Keep the failure visible without putting command output in the trail.
        AUDIT.event("service_action_failed", unit=name, action=action,
                    exit=code, ip=ip, **AUDIT.actor(u))
    return {"code": code, "output": out[-4000:]}


# ---------- containers ----------

#: Docker names: must start alphanumeric (a leading "-" would be parsed as a
#: docker CLI flag), then alphanumerics, dot, underscore or dash.
CONTAINER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")


@router.get("/api/containers")
async def containers_list(dach_sid: str | None = Cookie(default=None)):
    await P.require("containers_view", dach_sid)
    return await asyncio.to_thread(M.containers)


@router.get("/api/containers/{name}/logs")
async def containers_logs(name: str, tail: int = 200,
                          dach_sid: str | None = Cookie(default=None)):
    u = await P.require("containers_view", dach_sid)
    if not CONTAINER_RE.fullmatch(name):
        raise HTTPException(400, "bad container name")
    n = max(1, min(tail, 1000))
    AUDIT.event("container_logs", container=name, tail=n, **AUDIT.actor(u))
    return {"logs": await asyncio.to_thread(M.container_logs, name, n)}


@router.post("/api/containers/{name}/{action}")
async def containers_action(name: str, action: str, request: Request,
                            dach_sid: str | None = Cookie(default=None)):
    u = await P.require("containers_control", dach_sid)
    P.check_csrf(request, dach_sid)
    if not CONTAINER_RE.fullmatch(name):
        raise HTTPException(400, "bad container name")
    code, out = await asyncio.to_thread(M.container_action, name, action)
    AUDIT.event("container_action", container=name, action=action, exit=code,
                ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(u))
    return {"code": code, "output": out}

