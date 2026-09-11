"""Dachboard daemon. FastAPI. Binds loopback; expose via tunnel/nginx only."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import secrets
import subprocess
import time
from contextlib import asynccontextmanager, closing
from pathlib import Path

import yaml
from fastapi import Cookie, FastAPI, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import auth as A
from . import db as D
from . import files as F
from . import metrics as M
from . import runner as R
from . import tunnel as T
from .rbac import ADMIN_ONLY, RIGHTS, can, default_rights

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def load_config(path: str | None = None) -> dict:
    for cand in [path, "/opt/dachboard/config.yaml", str(ROOT / "config.yaml")]:
        if cand and Path(cand).exists():
            with open(cand) as f:
                return yaml.safe_load(f) or {}
    return {}


CFG = load_config()
DB = CFG.get("db_path", "/opt/dachboard/data/dachboard.sqlite3")
SECRET_FILE = CFG.get("secret_file", "/opt/dachboard/.secret")
COOKIE = "dach_sid"
LOGIN_FAILS: dict[str, list[float]] = {}


def secret() -> str:
    p = Path(SECRET_FILE)
    try:
        if p.exists():
            return p.read_text().strip()
        p.parent.mkdir(parents=True, exist_ok=True)
        s = secrets.token_hex(32)
        p.write_text(s)
        try:
            p.chmod(0o600)
        except OSError:
            pass
        return s
    except OSError:
        # read-only checkout (tests, audits): ephemeral, sessions stay in DB
        return secrets.token_hex(32)


SECRET = secret()


# ---------- users ----------

def get_user(uid: int) -> dict | None:
    with closing(D.connect(DB)) as con:
        r = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not r:
            return None
        return {"id": r["id"], "login": r["login"], "is_admin": bool(r["is_admin"]),
                "rights": D.jload(r["rights"], {}), "limits": D.jload(r["limits"], {}),
                "slot": r["slot"], "must_change_pw": bool(r["must_change_pw"])}


def get_user_by_login(login: str) -> dict | None:
    with closing(D.connect(DB)) as con:
        r = con.execute("SELECT * FROM users WHERE login=?", (login,)).fetchone()
        if not r:
            return None
        row = dict(r)
        return {"id": row["id"], "login": row["login"], "pass_hash": row["pass_hash"],
                "is_admin": bool(row["is_admin"]), "rights": D.jload(row["rights"], {}),
                "limits": D.jload(row["limits"], {}), "slot": row["slot"],
                "must_change_pw": bool(row["must_change_pw"])}


def admin_exists() -> bool:
    with closing(D.connect(DB)) as con:
        return con.execute("SELECT 1 FROM users WHERE is_admin=1").fetchone() is not None


def setup_token_path() -> Path:
    return Path(DB).parent / ".setup_token"


def ensure_setup_token() -> str | None:
    """First-run one-time token. Returns None when bootstrap is done."""
    if admin_exists():
        return None
    p = setup_token_path()
    if p.exists():
        try:
            return p.read_text().strip() or None
        except OSError:
            return None
    import logging
    tok = A.new_token()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(tok)
    try:
        p.chmod(0o600)
    except OSError:
        pass
    logging.getLogger("dachboard").warning("SETUP TOKEN (one-time): %s", tok)
    return tok


async def session_user(token: str | None) -> dict | None:
    if not token:
        return None
    ttl = int(CFG.get("session_ttl_hours", 72)) * 3600
    with closing(D.connect(DB)) as con:
        r = con.execute("SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)).fetchone()
        if not r or r["expires_at"] < time.time():
            return None
        con.execute("UPDATE sessions SET expires_at=? WHERE token=?",
                    (int(time.time()) + ttl, token))
        con.commit()
    return get_user(r["user_id"])


async def require(right: str, token: str | None, request: Request | None = None) -> dict:
    if request is not None:
        t = token_subject(request)
        if t:
            if not can(t, right):
                raise HTTPException(403, "forbidden")
            return t
        authz = request.headers.get("authorization", "")
        if authz.lower().startswith("bearer "):
            raise HTTPException(401, "bad token")
    u = await session_user(token)
    if not u or not can(u, right):
        raise HTTPException(403 if u else 401, "forbidden")
    return u


def token_subject(request: Request) -> dict | None:
    """Machine auth: Authorization: Bearer <api-token>. Scoped rights."""
    import hashlib
    authz = request.headers.get("authorization", "")
    if not authz.lower().startswith("bearer "):
        return None
    digest = hashlib.sha256(authz[7:].strip().encode()).hexdigest()
    with closing(D.connect(DB)) as con:
        r = con.execute("SELECT id, rights FROM api_tokens WHERE token_hash=?",
                        (digest,)).fetchone()
        if not r:
            return None
        con.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?",
                    (int(time.time()), r["id"]))
        con.commit()
        return {"id": 0, "login": f"token#{r['id']}", "is_admin": False,
                "via": "token", "rights": D.jload(r["rights"], {}),
                "limits": {}, "slot": None}


def check_csrf(request: Request, token: str | None) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if token_subject(request):
        return  # bearer calls carry no cookies; nothing to forge
    want = None
    if token:
        with closing(D.connect(DB)) as con:
            r = con.execute("SELECT csrf FROM sessions WHERE token=?", (token,)).fetchone()
            want = r["csrf"] if r else None
    got = request.headers.get("x-csrf-token")
    if not want or not got or not secrets.compare_digest(want, got):
        raise HTTPException(403, "bad csrf")


def home_of(user: dict, slot: str | None = None) -> Path:
    if user["is_admin"] and slot:
        return Path(f"/home/{slot}")
    if user["slot"]:
        return Path(f"/home/{user['slot']}")
    raise HTTPException(403, "no home")


# ---------- app ----------

@asynccontextmanager
async def lifespan(app: FastAPI):
    D.init(DB)
    ensure_setup_token()
    task = asyncio.create_task(_sampler())
    yield
    task.cancel()


async def _sampler():
    tick = 0
    while True:
        try:
            s = await asyncio.to_thread(M.snapshot)
            with closing(D.connect(DB)) as con:
                con.execute(
                    "INSERT OR REPLACE INTO metrics(ts,cpu,mem_used,mem_total,"
                    "disk_used,disk_total,temp,load1) VALUES(?,?,?,?,?,?,?,?)",
                    (s["ts"], s["cpu"], s["mem"]["used"], s["mem"]["total"],
                     s["disk"]["used"], s["disk"]["total"],
                     (s["temps"].get("x86_pkg_temp")
                      or next(iter(s["temps"].values()), 0)),
                     s["load"][0]))
                con.commit()
            D.prune_metrics(DB)
            tick += 1
            if tick % 10 == 0:
                # keep tunnel_url.txt fresh for external access-granter bots
                t = CFG.get("tunnel", {})
                try:
                    await asyncio.to_thread(
                        T.current, t.get("provider", ""), t.get("args", []),
                        int(t.get("cache_seconds", 30)), t.get("cache_file"))
                except Exception:
                    pass
        except Exception:
            pass
        await asyncio.sleep(30)


app = FastAPI(title="dachboard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")


@app.get("/")
def index():
    return FileResponse(str(ROOT / "static" / "index.html"))


# ---------- auth ----------

@app.get("/api/setup-needed")
async def setup_needed():
    return {"needed": not admin_exists()}


@app.post("/api/setup")
async def setup(request: Request):
    """One-time bootstrap: create first admin. Burns the token file."""
    if admin_exists():
        raise HTTPException(404, "already set up")
    body = await request.json()
    p = setup_token_path()
    try:
        want = p.read_text().strip()
    except OSError:
        want = ""
    got = str(body.get("token", ""))
    if not want or not secrets.compare_digest(got, want):
        raise HTTPException(403, "bad token")
    login = str(body.get("login", "")).strip()
    password = str(body.get("password", ""))
    if not login or len(login) > 32 or len(password) < 12:
        raise HTTPException(400, "login required, password min 12")
    with closing(D.connect(DB)) as con:
        con.execute(
            "INSERT INTO users(login,pass_hash,is_admin,rights,limits,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (login, A.hash_password(password), 1,
             json.dumps({r: True for r in RIGHTS}), "{}", int(time.time())))
        con.commit()
    try:
        p.unlink()
    except OSError:
        pass
    return {"ok": True}


@app.post("/api/login")
async def login(request: Request, response: Response):
    body = await request.json()
    ip = request.client.host if request.client else "?"
    fails = [t for t in LOGIN_FAILS.get(ip, []) if time.time() - t < 600]
    if len(fails) >= 10:
        raise HTTPException(429, "slow down")
    u = get_user_by_login(str(body.get("login", "")))
    if not u or not A.verify_password(str(body.get("password", "")), u["pass_hash"]):
        fails.append(time.time())
        LOGIN_FAILS[ip] = fails
        raise HTTPException(401, "bad credentials")
    if u.get("must_change_pw"):
        raise HTTPException(401, {"must_change": True})
    LOGIN_FAILS.pop(ip, None)
    tok, csrf = A.new_token(), A.new_token(16)
    ttl = int(CFG.get("session_ttl_hours", 72)) * 3600
    with closing(D.connect(DB)) as con:
        con.execute("INSERT INTO sessions(token,user_id,csrf,expires_at,created_at)"
                    " VALUES(?,?,?,?,?)",
                    (tok, u["id"], csrf, int(time.time()) + ttl, int(time.time())))
        con.commit()
    response.set_cookie(COOKIE, tok, httponly=True,
                        secure=bool(CFG.get("cookie_secure", True)),
                        samesite="lax", path="/", max_age=ttl)
    return {"csrf": csrf, "user": {k: v for k, v in u.items() if k != "pass_hash"}}


@app.post("/api/logout")
async def logout(request: Request, response: Response,
                 dach_sid: str | None = Cookie(default=None)):
    check_csrf(request, dach_sid)
    if dach_sid:
        with closing(D.connect(DB)) as con:
            con.execute("DELETE FROM sessions WHERE token=?", (dach_sid,))
            con.commit()
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
async def me(dach_sid: str | None = Cookie(default=None)):
    u = await session_user(dach_sid)
    if not u:
        raise HTTPException(401, "no session")
    return u


@app.post("/api/me/password")
async def me_password(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await session_user(dach_sid)
    if not u:
        raise HTTPException(401, "no session")
    check_csrf(request, dach_sid)
    body = await request.json()
    with closing(D.connect(DB)) as con:
        r = con.execute("SELECT pass_hash FROM users WHERE id=?", (u["id"],)).fetchone()
        if not r or not A.verify_password(str(body.get("old_password", "")), r["pass_hash"]):
            raise HTTPException(401, "bad old password")
        new = str(body.get("new_password", ""))
        if len(new) < 8:
            raise HTTPException(400, "password min 8")
        con.execute("UPDATE users SET pass_hash=?, must_change_pw=0 WHERE id=?",
                    (A.hash_password(new), u["id"]))
        con.commit()
    return {"ok": True}


@app.post("/api/first-password")
async def first_password(request: Request):
    """Pre-registered user sets their own password on first login. No session."""
    body = await request.json()
    ip = request.client.host if request.client else "?"
    u = get_user_by_login(str(body.get("login", "")))
    new = str(body.get("new_password", ""))
    if (not u or not u.get("must_change_pw")
            or not A.verify_password(str(body.get("old_password", "")), u["pass_hash"])):
        fails = [t for t in LOGIN_FAILS.get(ip, []) if time.time() - t < 600]
        fails.append(time.time())
        LOGIN_FAILS[ip] = fails
        raise HTTPException(401, "bad credentials")
    if len(new) < 8:
        raise HTTPException(400, "password min 8")
    with closing(D.connect(DB)) as con:
        con.execute("UPDATE users SET pass_hash=?, must_change_pw=0 WHERE id=?",
                    (A.hash_password(new), u["id"]))
        con.commit()
    return {"ok": True}


@app.get("/api/auth-check")
async def auth_check(request: Request, target: str = "", slot: str = "",
                     dach_sid: str | None = Cookie(default=None)):
    """nginx auth_request gate. 204 = pass."""
    u = await session_user(dach_sid)
    if not u:
        return Response(status_code=401)
    if target == "term":
        if not can(u, "terminal"):
            return Response(status_code=403)
        if not u["is_admin"] and slot and slot != (u["slot"] or ""):
            return Response(status_code=403)
    return Response(status_code=204)


# ---------- metrics / overview ----------

@app.get("/api/metrics")
async def metrics_live(dach_sid: str | None = Cookie(default=None)):
    await require("overview", dach_sid)
    return await asyncio.to_thread(M.snapshot)


@app.get("/api/metrics/history")
async def metrics_history(dach_sid: str | None = Cookie(default=None)):
    await require("overview", dach_sid)
    with closing(D.connect(DB)) as con:
        rows = con.execute(
            "SELECT * FROM metrics ORDER BY ts DESC LIMIT 288").fetchall()
    return [dict(r) for r in reversed(rows)]


@app.get("/api/services")
async def services(dach_sid: str | None = Cookie(default=None)):
    await require("overview", dach_sid)
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


# ---------- containers ----------

@app.get("/api/containers")
async def containers_list(dach_sid: str | None = Cookie(default=None)):
    await require("containers_view", dach_sid)
    return await asyncio.to_thread(M.containers)


@app.get("/api/containers/{name}/logs")
async def containers_logs(name: str, tail: int = 200,
                          dach_sid: str | None = Cookie(default=None)):
    await require("containers_view", dach_sid)
    return {"logs": await asyncio.to_thread(M.container_logs, name, tail)}


@app.post("/api/containers/{name}/{action}")
async def containers_action(name: str, action: str, request: Request,
                            dach_sid: str | None = Cookie(default=None)):
    u = await require("containers_control", dach_sid)
    check_csrf(request, dach_sid)
    code, out = await asyncio.to_thread(M.container_action, name, action)
    return {"code": code, "output": out}


# ---------- files ----------

@app.get("/api/files")
async def files_list(path: str = "", slot: str = "",
                     dach_sid: str | None = Cookie(default=None)):
    u = await require("files", dach_sid)
    try:
        return F.list_dir(home_of(u, slot or None), path)
    except (PermissionError, NotADirectoryError, OSError) as e:
        raise HTTPException(400, str(e))


@app.get("/api/files/read")
async def files_read(path: str, slot: str = "",
                     dach_sid: str | None = Cookie(default=None)):
    u = await require("files", dach_sid)
    try:
        return {"content": F.read_text(home_of(u, slot or None), path)}
    except (PermissionError, OSError, ValueError) as e:
        raise HTTPException(400, str(e))


@app.post("/api/files/write")
async def files_write(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await require("files", dach_sid)
    check_csrf(request, dach_sid)
    body = await request.json()
    try:
        F.write_text(home_of(u, body.get("slot") or None),
                     body.get("path", ""), body.get("content", ""))
        return {"ok": True}
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))


@app.post("/api/files/mkdir")
async def files_mkdir(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await require("files", dach_sid)
    check_csrf(request, dach_sid)
    body = await request.json()
    try:
        F.mkdir(home_of(u, body.get("slot") or None), body.get("path", ""))
        return {"ok": True}
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))


@app.post("/api/files/delete")
async def files_delete(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await require("files", dach_sid)
    check_csrf(request, dach_sid)
    body = await request.json()
    try:
        F.remove(home_of(u, body.get("slot") or None), body.get("path", ""))
        return {"ok": True}
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))


@app.post("/api/files/upload")
async def files_upload(request: Request, path: str = "", slot: str = "",
                       dach_sid: str | None = Cookie(default=None)):
    u = await require("files", dach_sid)
    check_csrf(request, dach_sid)
    form = await request.form()
    up: UploadFile = form.get("file")
    if not up:
        raise HTTPException(400, "no file")
    data = await up.read()
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(400, "too large")
    try:
        root = home_of(u, slot or None)
        dest = F.resolve(root, (path + "/" + (up.filename or "upload")).strip("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return {"ok": True, "size": len(data)}
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))


@app.get("/api/files/download")
async def files_download(path: str, slot: str = "",
                         dach_sid: str | None = Cookie(default=None)):
    u = await require("files", dach_sid)
    try:
        return FileResponse(str(F.resolve(home_of(u, slot or None), path)))
    except (PermissionError, OSError) as e:
        raise HTTPException(400, str(e))


@app.get("/api/quota")
async def quota(slot: str = "", dach_sid: str | None = Cookie(default=None)):
    u = await require("files", dach_sid)
    root = home_of(u, slot or None)
    used = await asyncio.to_thread(F.disk_usage, root)
    limit = (u.get("limits") or {}).get("disk_quota")
    return {"used": used, "limit": limit}


# ---------- commands ----------

def _cmd_row(r) -> dict:
    return {"id": r["id"], "name": r["name"],
            "argv": json.loads(r["argv"]), "run_as": r["run_as"],
            "allowed": json.loads(r["allowed"]), "timeout_sec": r["timeout_sec"]}


@app.get("/api/commands")
async def commands_list(dach_sid: str | None = Cookie(default=None)):
    u = await require("commands_run", dach_sid)
    with closing(D.connect(DB)) as con:
        rows = con.execute("SELECT * FROM commands ORDER BY name").fetchall()
    out = []
    for r in rows:
        c = _cmd_row(r)
        if u["is_admin"] or u["id"] in c["allowed"] or "*" in c["allowed"]:
            out.append(c)
    return out


@app.post("/api/commands")
async def commands_create(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await require("commands_edit", dach_sid)
    check_csrf(request, dach_sid)
    body = await request.json()
    argv = body.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise HTTPException(400, "argv must be string array (no shell)")
    with closing(D.connect(DB)) as con:
        try:
            cur = con.execute(
                "INSERT INTO commands(name,argv,run_as,allowed,timeout_sec,created_at)"
                " VALUES(?,?,?,?,?,?)",
                (body.get("name"), json.dumps(argv), body.get("run_as", "owner"),
                 json.dumps(body.get("allowed", [])), int(body.get("timeout_sec", 60)),
                 int(time.time())))
            con.commit()
            return {"id": cur.lastrowid}
        except Exception as e:
            raise HTTPException(400, str(e))


@app.put("/api/commands/{cid}")
async def commands_update(cid: int, request: Request,
                          dach_sid: str | None = Cookie(default=None)):
    await require("commands_edit", dach_sid)
    check_csrf(request, dach_sid)
    body = await request.json()
    argv = body.get("argv", [])
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise HTTPException(400, "argv must be string array (no shell)")
    with closing(D.connect(DB)) as con:
        con.execute("UPDATE commands SET name=?,argv=?,run_as=?,allowed=?,timeout_sec=?"
                    " WHERE id=?",
                    (body.get("name"), json.dumps(body.get("argv", [])),
                     body.get("run_as", "owner"), json.dumps(body.get("allowed", [])),
                     int(body.get("timeout_sec", 60)), cid))
        con.commit()
    return {"ok": True}


@app.delete("/api/commands/{cid}")
async def commands_delete(cid: int, request: Request,
                          dach_sid: str | None = Cookie(default=None)):
    await require("commands_edit", dach_sid)
    check_csrf(request, dach_sid)
    with closing(D.connect(DB)) as con:
        con.execute("DELETE FROM commands WHERE id=?", (cid,))
        con.commit()
    return {"ok": True}


@app.post("/api/commands/{cid}/run")
async def commands_run(cid: int, request: Request,
                       dach_sid: str | None = Cookie(default=None)):
    u = await require("commands_run", dach_sid)
    check_csrf(request, dach_sid)
    with closing(D.connect(DB)) as con:
        r = con.execute("SELECT * FROM commands WHERE id=?", (cid,)).fetchone()
        if not r:
            raise HTTPException(404, "no command")
        c = _cmd_row(r)
    if not (u["is_admin"] or u["id"] in c["allowed"] or "*" in c["allowed"]):
        raise HTTPException(403, "not allowed")
    run_as, use_slice = None, False
    if c["run_as"] == "owner" and u["slot"]:
        run_as, use_slice = u["slot"], True
    elif c["run_as"] not in ("", "owner", "self"):
        run_as = c["run_as"]
    lim = u.get("limits") or {}
    code, out = await asyncio.to_thread(
        R.run_as, c["argv"], run_as, c["timeout_sec"], use_slice,
        f"dach-{u['slot']}.slice" if use_slice and u["slot"] else None,
        lim.get("cpu_quota"), lim.get("mem_max"))
    with closing(D.connect(DB)) as con:
        con.execute("INSERT INTO runs(cmd_id,user_id,started_at,exit_code,output)"
                    " VALUES(?,?,?,?,?)",
                    (cid, u["id"], int(time.time()), code, out[-8000:]))
        con.commit()
    return {"code": code, "output": out}


@app.get("/api/runs")
async def runs_list(dach_sid: str | None = Cookie(default=None)):
    u = await require("commands_run", dach_sid)
    with closing(D.connect(DB)) as con:
        if u["is_admin"]:
            rows = con.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 50").fetchall()
        else:
            rows = con.execute("SELECT * FROM runs WHERE user_id=? ORDER BY id DESC LIMIT 50",
                               (u["id"],)).fetchall()
    return [dict(r) for r in rows]


# ---------- terminal ----------

def _slot_port(slot: str) -> int | None:
    slots: list = CFG.get("slots", [])
    if slot in slots:
        return int(CFG.get("ttyd", {}).get("port_base", 7681)) + slots.index(slot)
    return None


@app.post("/api/terminal/ensure")
async def terminal_ensure(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await require("terminal", dach_sid)
    check_csrf(request, dach_sid)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    slot = body.get("slot") or u["slot"]
    if not u["is_admin"] and slot != (u["slot"] or ""):
        raise HTTPException(403, "not yours")
    if not slot:
        raise HTTPException(400, "no slot")
    code, out = await asyncio.to_thread(
        R.run_as, ["systemctl", "start", f"dach-ttyd-{slot}.service"], None, 20)
    if code != 0:
        raise HTTPException(500, out[-500:])
    return {"slot": slot, "port": _slot_port(slot)}


# ---------- tunnel ----------

@app.get("/api/tunnel")
async def tunnel_url(request: Request, refresh: bool = False,
                     dach_sid: str | None = Cookie(default=None)):
    u = await require("tunnel_view", dach_sid, request)
    t = CFG.get("tunnel", {})
    if refresh:
        T.refresh()
    url = await asyncio.to_thread(
        T.current, t.get("provider", ""), t.get("args", []),
        int(t.get("cache_seconds", 30)), t.get("cache_file"))
    _ = u
    return {"url": url}


@app.post("/api/tunnel/refresh")
async def tunnel_refresh(request: Request, dach_sid: str | None = Cookie(default=None)):
    await require("tunnel_view", dach_sid, request)
    check_csrf(request, dach_sid)
    T.refresh()
    return {"ok": True}


# ---------- api tokens (machine access for bots/sites/any code) ----------

@app.get("/api/tokens")
async def tokens_list(dach_sid: str | None = Cookie(default=None)):
    await require("users_manage", dach_sid)
    with closing(D.connect(DB)) as con:
        rows = con.execute(
            "SELECT id,name,rights,created_at,last_used_at FROM api_tokens ORDER BY id").fetchall()
    return [{**dict(r), "rights": D.jload(r["rights"], {})} for r in rows]


@app.post("/api/tokens")
async def tokens_create(request: Request, dach_sid: str | None = Cookie(default=None)):
    await require("users_manage", dach_sid)
    check_csrf(request, dach_sid)
    body = await request.json()
    name = str(body.get("name", "")).strip()[:64] or "bot"
    rights = {r: bool(body.get("rights", {}).get(r, False)) for r in RIGHTS
              if r not in ADMIN_ONLY}
    tok, digest = A.api_token()
    with closing(D.connect(DB)) as con:
        try:
            cur = con.execute(
                "INSERT INTO api_tokens(name,token_hash,rights,created_at)"
                " VALUES(?,?,?,?)",
                (name, digest, json.dumps(rights), int(time.time())))
            con.commit()
            return {"id": cur.lastrowid, "token": tok}
        except Exception as e:
            raise HTTPException(400, str(e))


@app.delete("/api/tokens/{tid}")
async def tokens_delete(tid: int, request: Request,
                        dach_sid: str | None = Cookie(default=None)):
    await require("users_manage", dach_sid)
    check_csrf(request, dach_sid)
    with closing(D.connect(DB)) as con:
        con.execute("DELETE FROM api_tokens WHERE id=?", (tid,))
        con.commit()
    return {"ok": True}


# ---------- users (admin) ----------

@app.get("/api/users")
async def users_list(dach_sid: str | None = Cookie(default=None)):
    await require("users_manage", dach_sid)
    with closing(D.connect(DB)) as con:
        rows = con.execute(
            "SELECT id,login,is_admin,rights,limits,slot,must_change_pw,created_at"
            " FROM users ORDER BY id").fetchall()
    return [{**dict(r), "is_admin": bool(r["is_admin"]),
             "rights": D.jload(r["rights"], {}), "limits": D.jload(r["limits"], {}),
             "must_change_pw": bool(r["must_change_pw"])}
            for r in rows]


@app.post("/api/users")
async def users_create(request: Request, dach_sid: str | None = Cookie(default=None)):
    await require("users_manage", dach_sid)
    check_csrf(request, dach_sid)
    body = await request.json()
    login = str(body.get("login", "")).strip()
    if not login or len(login) > 32:
        raise HTTPException(400, "bad login")
    password = str(body.get("password") or "")
    if len(password) < 8:
        raise HTTPException(400, "password min 8")
    rights = {r: bool(body.get("rights", {}).get(r, False)) for r in RIGHTS}
    if body.get("is_admin"):
        rights = {r: True for r in RIGHTS}
    with closing(D.connect(DB)) as con:
        try:
            cur = con.execute(
                "INSERT INTO users(login,pass_hash,is_admin,rights,limits,slot,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (login, A.hash_password(password), 1 if body.get("is_admin") else 0,
                 json.dumps(rights), json.dumps(body.get("limits", {})),
                 body.get("slot"), int(time.time())))
            con.commit()
            return {"id": cur.lastrowid}
        except Exception as e:
            raise HTTPException(400, str(e))


@app.put("/api/users/{uid}")
async def users_update(uid: int, request: Request,
                       dach_sid: str | None = Cookie(default=None)):
    me_ = await require("users_manage", dach_sid)
    check_csrf(request, dach_sid)
    body = await request.json()
    sets, vals = [], []
    if "rights" in body:
        sets.append("rights=?")
        vals.append(json.dumps({r: bool(body["rights"].get(r, False)) for r in RIGHTS}))
    if "limits" in body:
        sets.append("limits=?")
        vals.append(json.dumps(body["limits"]))
    if "slot" in body:
        sets.append("slot=?")
        vals.append(body["slot"])
    if "password" in body and body["password"]:
        if len(body["password"]) < 8:
            raise HTTPException(400, "password min 8")
        sets.append("pass_hash=?")
        vals.append(A.hash_password(body["password"]))
        if body.get("must_change_pw"):
            sets.append("must_change_pw=?")
            vals.append(1)
    elif "must_change_pw" in body:
        sets.append("must_change_pw=?")
        vals.append(1 if body["must_change_pw"] else 0)
    if "is_admin" in body and uid != me_["id"]:
        sets.append("is_admin=?")
        vals.append(1 if body["is_admin"] else 0)
        if body["is_admin"]:
            sets.append("rights=?")
            vals.append(json.dumps({r: True for r in RIGHTS}))
    if not sets:
        return {"ok": True}
    with closing(D.connect(DB)) as con:
        con.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", (*vals, uid))
        con.commit()
        row = con.execute("SELECT slot, limits FROM users WHERE id=?", (uid,)).fetchone()
    quota_applied, quota_msg = False, ""
    if row and row["slot"]:
        from . import quota as Q
        lim = D.jload(row["limits"], {}).get("disk_quota")
        quota_applied, quota_msg = await asyncio.to_thread(Q.apply_quota, row["slot"], lim)
    return {"ok": True, "quota_applied": quota_applied, "quota_msg": quota_msg}


@app.delete("/api/users/{uid}")
async def users_delete(uid: int, request: Request,
                       dach_sid: str | None = Cookie(default=None)):
    me_ = await require("users_manage", dach_sid)
    check_csrf(request, dach_sid)
    if uid == me_["id"]:
        raise HTTPException(400, "no self-delete")
    with closing(D.connect(DB)) as con:
        con.execute("DELETE FROM users WHERE id=?", (uid,))
        con.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        con.commit()
    return {"ok": True}


@app.get("/api/rights")
async def rights_list(dach_sid: str | None = Cookie(default=None)):
    await require("users_manage", dach_sid)
    from .rbac import ADMIN_ONLY
    return {"rights": RIGHTS, "admin_only": sorted(ADMIN_ONLY)}


# ---------- cli ----------

def cli():
    ap = argparse.ArgumentParser(prog="dachboard")
    ap.add_argument("cmd", choices=["serve", "create-admin", "reconcile-quotas"])
    ap.add_argument("--config")
    a = ap.parse_args()
    global CFG, DB, SECRET_FILE, SECRET
    if a.config:
        CFG = load_config(a.config)
        DB = CFG.get("db_path", DB)
        SECRET_FILE = CFG.get("secret_file", SECRET_FILE)
        SECRET = secret()
    D.init(DB)
    if a.cmd == "create-admin":
        login = input("admin login [admin]: ").strip() or "admin"
        pw = getpass.getpass("password (min 8): ")
        if len(pw) < 8:
            raise SystemExit("too short")
        with closing(D.connect(DB)) as con:
            if con.execute("SELECT 1 FROM users WHERE login=?", (login,)).fetchone():
                raise SystemExit("exists")
            con.execute(
                "INSERT INTO users(login,pass_hash,is_admin,rights,limits,created_at)"
                " VALUES(?,?,?,?,?,?)",
                (login, A.hash_password(pw), 1,
                 json.dumps({r: True for r in RIGHTS}), "{}", int(time.time())))
            con.commit()
        print(f"admin {login} created")
    elif a.cmd == "reconcile-quotas":
        from . import quota as Q
        with closing(D.connect(DB)) as con:
            rows = con.execute("SELECT login, slot, limits FROM users WHERE slot IS NOT NULL").fetchall()
        for r in rows:
            lim = D.jload(r["limits"], {}).get("disk_quota")
            ok, msg = Q.apply_quota(r["slot"], lim)
            print(f"{r['login']}/{r['slot']}: {'OK' if ok else 'SKIP'} {lim} {msg}")
    elif a.cmd == "serve":
        import uvicorn
        uvicorn.run("app.main:app", host=CFG.get("host", "127.0.0.1"),
                    port=int(CFG.get("port", 8420)))


if __name__ == "__main__":
    cli()
