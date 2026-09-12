"""Dachboard daemon. FastAPI. Binds loopback; expose via tunnel/nginx only."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import time
from contextlib import asynccontextmanager, closing
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import auth as A
from . import db as D
from . import deps as P
from . import metrics as M
from . import tunnel as T
from .rbac import RIGHTS
from .routes import admin, auth, commands, files, overview, tunnel

# Backward compat: tests and old imports use app.main.X.
# CFG / LOGIN_FAILS share the same dict objects with deps;
# DB / SECRET_FILE / SECRET are rebound in cli(), keep them in sync.
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
_slot_port = P.slot_port
cmd_row = P.cmd_row
_cmd_row = P.cmd_row
UNIT_RE = P.UNIT_RE


@asynccontextmanager
async def lifespan(app: FastAPI):
    D.init(P.DB)
    P.ensure_setup_token()
    task = asyncio.create_task(_sampler())
    yield
    task.cancel()


async def _sampler():
    tick = 0
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
            tick += 1
            if tick % 10 == 0:
                t = P.CFG.get("tunnel", {})
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
app.mount("/static", StaticFiles(directory=str(P.ROOT / "static")), name="static")
app.include_router(auth.router)
app.include_router(overview.router)
app.include_router(files.router)
app.include_router(commands.router)
app.include_router(tunnel.router)
app.include_router(admin.router)


@app.get("/")
def index():
    return FileResponse(str(P.ROOT / "static" / "index.html"))


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
                 json.dumps({r: True for r in RIGHTS}), "{}", int(time.time())))
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
