import asyncio
import json
import time
from contextlib import closing

from fastapi import APIRouter, Cookie, HTTPException, Request

from .. import audit as AUDIT
from .. import db as D
from .. import deps as P
from .. import runner as R
from .. import security as SEC

router = APIRouter()
# ---------- commands ----------

@router.get("/api/commands")
async def commands_list(dach_sid: str | None = Cookie(default=None)):
    u = await P.require("commands_run", dach_sid)
    with closing(D.connect(P.DB)) as con:
        rows = con.execute("SELECT * FROM commands ORDER BY name").fetchall()
    out = []
    for r in rows:
        c = P.cmd_row(r)
        if u["is_admin"] or u["id"] in c["allowed"] or "*" in c["allowed"]:
            out.append(c)
    return out


@router.post("/api/commands")
async def commands_create(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("commands_edit", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    argv = body.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise HTTPException(400, "argv must be string array (no shell)")
    run_as = body.get("run_as", "owner")
    with closing(D.connect(P.DB)) as con:
        try:
            cur = con.execute(
                "INSERT INTO commands(name,argv,run_as,allowed,timeout_sec,created_at)"
                " VALUES(?,?,?,?,?,?)",
                (body.get("name"), json.dumps(argv), run_as,
                 json.dumps(body.get("allowed", [])), int(body.get("timeout_sec", 60)),
                 int(time.time())))
            con.commit()
        except Exception as e:
            raise HTTPException(400, str(e)) from None
    # A preset command is a stored root-side execution primitive: who defined
    # it, and to run as whom, is the part worth keeping.
    AUDIT.event("command_create", cmd_id=cur.lastrowid, cmd=body.get("name"),
                run_as=run_as, ip=SEC.client_ip(request, P.CFG),
                **AUDIT.actor(u))
    return {"id": cur.lastrowid}


@router.put("/api/commands/{cid}")
async def commands_update(cid: int, request: Request,
                          dach_sid: str | None = Cookie(default=None)):
    u = await P.require("commands_edit", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    argv = body.get("argv", [])
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise HTTPException(400, "argv must be string array (no shell)")
    run_as = body.get("run_as", "owner")
    with closing(D.connect(P.DB)) as con:
        con.execute("UPDATE commands SET name=?,argv=?,run_as=?,allowed=?,timeout_sec=?"
                    " WHERE id=?",
                    (body.get("name"), json.dumps(argv), run_as,
                     json.dumps(body.get("allowed", [])),
                     int(body.get("timeout_sec", 60)), cid))
        con.commit()
    AUDIT.event("command_update", cmd_id=cid, cmd=body.get("name"),
                run_as=run_as, ip=SEC.client_ip(request, P.CFG),
                **AUDIT.actor(u))
    return {"ok": True}


@router.delete("/api/commands/{cid}")
async def commands_delete(cid: int, request: Request,
                          dach_sid: str | None = Cookie(default=None)):
    u = await P.require("commands_edit", dach_sid)
    P.check_csrf(request, dach_sid)
    with closing(D.connect(P.DB)) as con:
        row = con.execute("SELECT name FROM commands WHERE id=?", (cid,)).fetchone()
        con.execute("DELETE FROM commands WHERE id=?", (cid,))
        con.commit()
    AUDIT.event("command_delete", cmd_id=cid, cmd=row["name"] if row else "-",
                ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(u))
    return {"ok": True}


@router.post("/api/commands/{cid}/run")
async def commands_run(cid: int, request: Request,
                       dach_sid: str | None = Cookie(default=None)):
    u = await P.require("commands_run", dach_sid)
    P.check_csrf(request, dach_sid)
    with closing(D.connect(P.DB)) as con:
        r = con.execute("SELECT * FROM commands WHERE id=?", (cid,)).fetchone()
        if not r:
            raise HTTPException(404, "no command")
        c = P.cmd_row(r)
    if not (u["is_admin"] or u["id"] in c["allowed"] or "*" in c["allowed"]):
        AUDIT.denied(u, f"commands_run:{c['name']}")
        raise HTTPException(403, "not allowed")
    run_as, use_slice = None, False
    use_container = False
    if c["run_as"] == "owner" and u["slot"]:
        from .. import slots as S
        if S.container_exists(u["slot"]):
            use_container = True  # isolated slot: run inside its container
        else:
            run_as, use_slice = u["slot"], True
    elif c["run_as"] not in ("", "owner", "self"):
        run_as = c["run_as"]
    lim = u.get("limits") or {}
    if use_container:
        code, out = await asyncio.to_thread(
            R.exec_in, u["slot"], c["argv"], c["timeout_sec"])
    else:
        code, out = await asyncio.to_thread(
            R.run_as, c["argv"], run_as, c["timeout_sec"], use_slice,
            f"dach-{u['slot']}.slice" if use_slice and u["slot"] else None,
            lim.get("cpu_quota"), lim.get("mem_max"))
    with closing(D.connect(P.DB)) as con:
        con.execute("INSERT INTO runs(cmd_id,user_id,started_at,exit_code,output)"
                    " VALUES(?,?,?,?,?)",
                    (cid, u["id"], int(time.time()), code, out[-8000:]))
        con.commit()
    # `runs` keeps the output; the audit line keeps the *identity* of the
    # execution — including the effective uid, which is what decides whether
    # this was a slot command or a root one.
    AUDIT.event("command_run", cmd_id=cid, cmd=c["name"], exit=code,
                effective_user=run_as or ("container" if use_container else "root"),
                **AUDIT.actor(u))
    return {"code": code, "output": out}


@router.get("/api/runs")
async def runs_list(dach_sid: str | None = Cookie(default=None)):
    u = await P.require("commands_run", dach_sid)
    with closing(D.connect(P.DB)) as con:
        if u["is_admin"]:
            rows = con.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 50").fetchall()
        else:
            rows = con.execute("SELECT * FROM runs WHERE user_id=? ORDER BY id DESC LIMIT 50",
                               (u["id"],)).fetchall()
    return [dict(r) for r in rows]


# ---------- terminal ----------

@router.post("/api/terminal/ensure")
async def terminal_ensure(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.require("terminal", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    # no slot exposed outside: admin lands in root, others in their own slot
    slot = body.get("slot") or u["slot"] or ("root" if u["is_admin"] else None)
    if slot == "root" and not u["is_admin"]:
        AUDIT.denied(u, "terminal:root")
        raise HTTPException(403, "admin only")
    if not u["is_admin"] and slot != (u["slot"] or ""):
        AUDIT.denied(u, f"terminal:{slot}")
        raise HTTPException(403, "not yours")
    if not slot:
        raise HTTPException(400, "no slot")
    unit = "dach-ttyd-root.service" if slot == "root" else f"dach-ttyd-{slot}.service"
    code, out = await asyncio.to_thread(
        R.run_as, ["systemctl", "start", unit], None, 20)
    if code != 0:
        AUDIT.event("terminal_ensure_failed", slot=slot, unit=unit, exit=code,
                    ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(u))
        raise HTTPException(500, out[-500:])
    AUDIT.event("terminal_ensure", slot=slot, unit=unit,
                ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(u))
    return {"slot": slot, "port": P.slot_port(slot)}


@router.post("/api/terminal/restart")
async def terminal_restart(request: Request, dach_sid: str | None = Cookie(default=None)):
    """Kill the tmux session so the next attach starts a fresh shell.
    The ttyd unit itself keeps running (ensure starts it if down)."""
    u = await P.require("terminal", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    slot = body.get("slot") or u["slot"] or ("root" if u["is_admin"] else None)
    if slot == "root" and not u["is_admin"]:
        AUDIT.denied(u, "terminal:root")
        raise HTTPException(403, "admin only")
    if not u["is_admin"] and slot != (u["slot"] or ""):
        AUDIT.denied(u, f"terminal:{slot}")
        raise HTTPException(403, "not yours")
    if not slot:
        raise HTTPException(400, "no slot")
    argv = ["tmux", "-L", f"dach-{slot}", "kill-session", "-t", "main"]
    # `killed` False is the normal first-attach case (no session yet), so the
    # tmux output carries nothing worth keeping.
    if slot == "root":
        code, _out = await asyncio.to_thread(R.run_as, argv, None, 20)
    else:
        code, _out = await asyncio.to_thread(R.run_as, argv, slot, 20)
    killed = code == 0
    # make sure the gateway is up for the reattach
    unit = "dach-ttyd-root.service" if slot == "root" else f"dach-ttyd-{slot}.service"
    await asyncio.to_thread(R.run_as, ["systemctl", "start", unit], None, 20)
    AUDIT.event("terminal_restart", slot=slot, killed=int(killed),
                ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(u))
    return {"slot": slot, "port": P.slot_port(slot), "killed": killed}
