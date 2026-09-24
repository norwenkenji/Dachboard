"""Dachboard daemon. FastAPI. Binds loopback; expose via tunnel/nginx only."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import time
from contextlib import asynccontextmanager, closing

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from . import assets as ASSETS
from . import audit as AUDIT
from . import auth as A
from . import db as D
from . import deps as P
from . import files as F
from . import metrics as M
from . import security as SEC
from . import tunnel as T
from .rbac import RIGHTS
from .routes import admin, auth, commands, files, overview, tunnel

log = logging.getLogger("dachboard")


def _setup_logging(cfg: dict | None = None) -> None:
    """Give ``dachboard`` a stderr handler once, at WARNING by default.

    systemd routes stderr to the journal, so this is all the panel needs in
    production. ``logging.basicConfig`` is not used: it would also capture
    uvicorn's own loggers, whose format is deliberately different.
    """
    if log.handlers:
        return
    lvl = str((cfg or {}).get("log_level", "WARNING")).upper()
    log.setLevel(getattr(logging, lvl, logging.WARNING))
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"))
    log.addHandler(h)
    log.propagate = False


# Backward compat: tests and old imports use app.main.X.
# These alias the deps module so there is one source of truth — CFG/LOGIN_FAILS
# share the same objects, while DB/SECRET_FILE/SECRET are rebound in cli() and
# must be re-pointed there too (the one place a sync can be forgotten).
CFG = P.CFG
DB = P.DB
SECRET_FILE = P.SECRET_FILE
SECRET = P.SECRET
COOKIE = P.COOKIE
LOGIN_FAILS = P.LOGIN_FAILS
load_config = P.load_config
secret = P.secret
get_user = P.get_user
get_user_by_login = P.get_user_by_login
admin_exists = P.admin_exists
setup_token_path = P.setup_token_path
ensure_setup_token = P.ensure_setup_token
session_user = P.session_user
require = P.require
token_subject = P.token_subject
check_csrf = P.check_csrf
home_of = P.home_of
slot_port = P.slot_port
cmd_row = P.cmd_row
UNIT_RE = P.UNIT_RE


@asynccontextmanager
async def lifespan(app: FastAPI):
    _setup_logging(P.CFG)
    D.init(P.DB)
    AUDIT.configure(P.CFG)
    AUDIT.event(AUDIT.BOOT, host=M.host_info().get("hostname"),
                backend=F.BACKEND, pid=os.getpid())
    P.ensure_setup_token()
    task = asyncio.create_task(_sampler())
    house = asyncio.create_task(_housekeeping())
    yield
    task.cancel()
    house.cancel()


async def _sampler():
    """Metrics writer. Errors are logged, not swallowed.

    This used to be ``except Exception: pass``, which meant a permanently broken
    sampler — a full disk, a schema change, a dead /proc — produced an empty
    dashboard and no clue why, forever.
    """
    tick = 0
    backoff = 0
    while True:
        try:
            s = await asyncio.to_thread(M.snapshot)
            with closing(D.connect(P.DB)) as con:
                con.execute(
                    "INSERT OR REPLACE INTO metrics(ts,cpu,mem_used,mem_total,"
                    "disk_used,disk_total,temp,load1) VALUES(?,?,?,?,?,?,?,?)",
                    (s["ts"], s["cpu"], s["mem"]["used"], s["mem"]["total"],
                     s["disk"]["used"], s["disk"]["total"],
                     (s["temps"].get("x86_pkg_temp")
                      or next(iter(s["temps"].values()), 0)),
                     s["load"][0]))
                con.commit()
            D.prune_metrics(P.DB)
            backoff = 0
            tick += 1
            if tick % 10 == 0:
                t = P.CFG.get("tunnel", {})
                try:
                    await asyncio.to_thread(
                        T.current, t.get("provider", ""), t.get("args", []),
                        int(t.get("cache_seconds", 30)), t.get("cache_file"))
                except Exception:
                    # A tunnel probe failing is routine (no provider configured,
                    # container absent) — but it should still be visible once.
                    log.exception("tunnel probe failed")
        except Exception:
            log.exception("metrics sample failed")
            # Repeated failures must not spin at 30s intervals forever.
            backoff = min(backoff + 30, 600) if backoff else 30
        await asyncio.sleep(30 + backoff)


async def _housekeeping():
    """Periodic cleanup the request path should not pay for.

    Expired sessions are never deleted on logout-or-expiry otherwise, and every
    authenticated request writes to that table (the sliding TTL), so an
    ever-growing `sessions` slows the hot path.
    """
    while True:
        await asyncio.sleep(3600)
        try:
            n = await asyncio.to_thread(D.prune_sessions, P.DB)
            if n:
                AUDIT.event("sessions_pruned", count=n)
        except Exception:
            log.exception("session GC failed")


app = FastAPI(title="dachboard", lifespan=lifespan)


@app.middleware("http")
async def current_request(request, call_next):
    """Expose the request to P.require() in endpoints that don't declare it,
    so Bearer API tokens work on every route (not just the two that pass it)."""
    tok = P.CURRENT_REQUEST.set(request)
    try:
        return await call_next(request)
    finally:
        P.CURRENT_REQUEST.reset(tok)


@app.middleware("http")
async def security_headers(request, call_next):
    """Harden every response.

    Registered after ``current_request`` so it wraps it — headers land on the
    response that actually leaves the app. Values an endpoint set itself win:
    ``setdefault`` keeps the file preview's own CSP and ``SAMEORIGIN`` framing.
    """
    response = await call_next(request)
    sec = P.CFG.get("security", {}) or {}
    for k, v in SEC.security_headers(
            hsts=bool(sec.get("hsts", True)),
            hsts_max_age=int(sec.get("hsts_max_age", 31536000))).items():
        response.headers.setdefault(k, v)
    # Versioned static assets are cache-busted by a content hash in ?v= (see
    # app/assets.py), so a changed file means a changed URL and they may be
    # cached — bounded, because the hash covers the file, not the shell that
    # points at it. Everything else (the SPA shell, APIs, user bytes) is never
    # stored: a cached shell would keep pointing at old asset URLs.
    if request.url.path.startswith(("/static/", "/mcp/")):
        response.headers.setdefault("Cache-Control", "public, max-age=86400")
    else:
        response.headers["Cache-Control"] = "no-store"
    return response


app.mount("/static", StaticFiles(directory=str(P.ROOT / "static")), name="static")
if (P.ROOT / "mcp").is_dir():
    # MCP stdio server script — public download for the API tab
    app.mount("/mcp", StaticFiles(directory=str(P.ROOT / "mcp")), name="mcp")
app.include_router(auth.router)
app.include_router(overview.router)
app.include_router(files.router)
app.include_router(commands.router)
app.include_router(tunnel.router)
app.include_router(admin.router)

_shell = ASSETS.ShellRenderer(P.ROOT)


@app.get("/")
def index():
    """The SPA shell, with every asset URL versioned by content hash.

    Rendered rather than sent as a file, so a ``?v=`` bump is never something a
    human has to remember. The renderer caches by mtime, so this costs one
    string substitution in steady state, not eleven hashes per request.
    """
    return HTMLResponse(_shell.render())


def cli():
    ap = argparse.ArgumentParser(prog="dachboard")
    ap.add_argument("cmd", choices=["serve", "create-admin", "reconcile-quotas",
                                    "rotate-password"])
    ap.add_argument("--config")
    ap.add_argument("--login", default="")
    a = ap.parse_args()
    global CFG, DB, SECRET_FILE, SECRET
    if a.config:
        P.CFG = load_config(a.config)
        CFG = P.CFG
        P.DB = CFG.get("db_path", P.DB)
        DB = P.DB
        P.SECRET_FILE = CFG.get("secret_file", P.SECRET_FILE)
        SECRET_FILE = P.SECRET_FILE
        P.SECRET = secret()
        SECRET = P.SECRET
    _setup_logging(P.CFG)
    D.init(P.DB)
    if a.cmd == "create-admin":
        login = input("admin login [admin]: ").strip() or "admin"
        pw = getpass.getpass("password (min 8): ")
        if len(pw) < 8:
            raise SystemExit("too short")
        with closing(D.connect(P.DB)) as con:
            if con.execute("SELECT 1 FROM users WHERE login=?", (login,)).fetchone():
                raise SystemExit("exists")
            con.execute(
                "INSERT INTO users(login,pass_hash,is_admin,rights,limits,created_at)"
                " VALUES(?,?,?,?,?,?)",
                (login, A.hash_password(pw), 1,
                 json.dumps(dict.fromkeys(RIGHTS, True)), "{}", int(time.time())))
            con.commit()
        print(f"admin {login} created")
    elif a.cmd == "rotate-password":
        # Compromised/old password rotation without shell SQL.
        login = a.login or input("login: ").strip()
        pw = getpass.getpass("new password (min 8): ")
        if len(pw) < 8:
            raise SystemExit("too short")
        with closing(D.connect(P.DB)) as con:
            r = con.execute("SELECT id FROM users WHERE login=?", (login,)).fetchone()
            if not r:
                raise SystemExit("no such user")
            con.execute("UPDATE users SET pass_hash=?, must_change_pw=0 WHERE id=?",
                        (A.hash_password(pw), r["id"]))
            con.execute("DELETE FROM sessions WHERE user_id=?", (r["id"],))
            con.commit()
        print(f"password rotated for {login}, sessions revoked")
    elif a.cmd == "reconcile-quotas":
        from . import quota as Q
        with closing(D.connect(P.DB)) as con:
            rows = con.execute("SELECT login, slot, limits FROM users WHERE slot IS NOT NULL").fetchall()
        for r in rows:
            lim = D.jload(r["limits"], {}).get("disk_quota")
            ok, msg = Q.apply_quota(r["slot"], lim)
            print(f"{r['login']}/{r['slot']}: {'OK' if ok else 'SKIP'} {lim} {msg}")
    elif a.cmd == "serve":
        import uvicorn
        uvicorn.run("app.main:app", host=P.CFG.get("host", "127.0.0.1"),
                    port=int(P.CFG.get("port", 8420)))


if __name__ == "__main__":
    cli()
