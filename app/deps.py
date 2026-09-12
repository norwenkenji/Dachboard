"""Shared deps for routers. Single source of truth (CFG/DB/etc)."""
from __future__ import annotations

import json
import re
import secrets
import time
from contextlib import closing
from pathlib import Path

import yaml
from fastapi import HTTPException, Request

from . import auth as A
from . import db as D
from .rbac import can

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
        return secrets.token_hex(32)


SECRET = secret()


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


def token_subject(request: Request) -> dict | None:
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


def check_csrf(request: Request, token: str | None) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if token_subject(request):
        return
    want = None
    if token:
        with closing(D.connect(DB)) as con:
            r = con.execute("SELECT csrf FROM sessions WHERE token=?", (token,)).fetchone()
            want = r["csrf"] if r else None
    got = request.headers.get("x-csrf-token")
    if not want or not got or not secrets.compare_digest(want, got):
        raise HTTPException(403, "bad csrf")


def home_of(user: dict, slot: str | None = None) -> Path:
    if user["is_admin"]:
        return Path(f"/home/{slot}") if slot else Path("/")
    tgt = slot or user["slot"]
    if not tgt or (slot and slot != user["slot"]):
        raise HTTPException(403, "no home")
    return Path(f"/home/{tgt}")


def slot_port(slot: str) -> int | None:
    if slot == "root":
        return int(CFG.get("ttyd", {}).get("port_base", 7681)) - 1
    slots: list = CFG.get("slots", [])
    if slot in slots:
        return int(CFG.get("ttyd", {}).get("port_base", 7681)) + slots.index(slot)
    return None


def cmd_row(r) -> dict:
    return {"id": r["id"], "name": r["name"],
            "argv": json.loads(r["argv"]), "run_as": r["run_as"],
            "allowed": json.loads(r["allowed"]), "timeout_sec": r["timeout_sec"]}


UNIT_RE = re.compile(r"^[A-Za-z0-9@.:_-]+\.(service|socket|timer|target)$")
