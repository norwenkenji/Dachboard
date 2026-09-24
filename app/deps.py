"""Shared deps for routers. Single source of truth (CFG/DB/etc)."""
from __future__ import annotations

import json
import logging
import re
import secrets
import time
from contextlib import closing, suppress
from contextvars import ContextVar
from pathlib import Path

import yaml
from fastapi import HTTPException, Request

from . import audit as AUDIT
from . import auth as A
from . import db as D
from . import security as SEC
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

#: Login throttle. The window and the cap are what an operator tunes; the key
#: bound is what keeps a flood of distinct source addresses from turning the
#: dict into an unbounded memory leak.
LOGIN_FAIL_WINDOW = 600          # seconds a failure counts for
LOGIN_FAIL_MAX = 10              # failures inside the window -> 429
LOGIN_FAIL_MAX_KEYS = 4096       # tracked addresses before the oldest is evicted

# Set by the request middleware so require()/check_csrf() see the request even
# in endpoints that don't declare it. Lets Bearer tokens work on every route.
CURRENT_REQUEST: ContextVar[Request | None] = ContextVar("current_request", default=None)


def _prune(ts: list[float], now: float) -> list[float]:
    """Drop entries older than the window, in place-safe fashion."""
    return [t for t in ts if now - t < LOGIN_FAIL_WINDOW]


def login_blocked(ip: str) -> bool:
    """Whether this address has burned its budget inside the window."""
    return len(_prune(LOGIN_FAILS.get(ip, []), time.time())) >= LOGIN_FAIL_MAX


def note_login_failure(ip: str) -> int:
    """Record a failed attempt; returns how many are live in the window.

    Stale buckets are dropped here rather than on read, and the dict is capped:
    without either, one sweep of spoofed addresses (or simply months of uptime
    behind a NAT pool) grows it forever.
    """
    now = time.time()
    fails = _prune(LOGIN_FAILS.get(ip, []), now)
    fails.append(now)
    LOGIN_FAILS[ip] = fails
    if len(LOGIN_FAILS) > LOGIN_FAIL_MAX_KEYS:
        for k in sorted(LOGIN_FAILS, key=lambda k: max(LOGIN_FAILS[k] or [0]))[
                :len(LOGIN_FAILS) - LOGIN_FAIL_MAX_KEYS]:
            del LOGIN_FAILS[k]
    return len(fails)


def clear_login_failures(ip: str) -> None:
    LOGIN_FAILS.pop(ip, None)


def secret() -> str:
    p = Path(SECRET_FILE)
    try:
        if p.exists():
            return p.read_text().strip()
        p.parent.mkdir(parents=True, exist_ok=True)
        s = secrets.token_hex(32)
        p.write_text(s)
        with suppress(OSError):
            p.chmod(0o600)
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
    tok = A.new_token()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(tok)
    with suppress(OSError):
        p.chmod(0o600)
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
        r = con.execute("SELECT id, rights, slot, is_admin FROM api_tokens WHERE token_hash=?",
                        (digest,)).fetchone()
        if not r:
            return None
        con.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?",
                    (int(time.time()), r["id"]))
        con.commit()
        return {"id": 0, "login": f"token#{r['id']}", "is_admin": bool(r["is_admin"]),
                "via": "token", "rights": D.jload(r["rights"], {}),
                "limits": {}, "slot": r["slot"]}


async def require(right: str, token: str | None, request: Request | None = None) -> dict:
    if request is None:
        request = CURRENT_REQUEST.get()
    if request is not None:
        t = token_subject(request)
        if t:
            if not can(t, right):
                AUDIT.denied(t, right, SEC.client_ip(request, CFG))
                raise HTTPException(403, "forbidden")
            return t
        authz = request.headers.get("authorization", "")
        if authz.lower().startswith("bearer "):
            # A presented-but-unknown token is worth recording: it is either a
            # revoked token still in use somewhere, or someone guessing.
            AUDIT.event("bad_token", right=right,
                        ip=SEC.client_ip(request, CFG))
            raise HTTPException(401, "bad token")
    u = await session_user(token)
    if not u:
        # Anonymous 401s are routine (the SPA probes /api/me before login), so
        # they are deliberately not audited — only real denials are.
        raise HTTPException(401, "forbidden")
    if not can(u, right):
        AUDIT.denied(u, right,
                     SEC.client_ip(request, CFG) if request is not None else None)
        raise HTTPException(403, "forbidden")
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
        # A rejected CSRF check on a live session is either a stale tab or a
        # cross-site request someone just attempted. Either way: one line.
        AUDIT.event("csrf_rejected", method=request.method,
                    path=request.url.path, ip=SEC.client_ip(request, CFG))
        raise HTTPException(403, "bad csrf")


SLOT_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def home_of(user: dict, slot: str | None = None) -> Path:
    # a slot name becomes a path component: never trust it unvalidated
    if slot is not None and not SLOT_RE.fullmatch(slot):
        raise HTTPException(400, "bad slot")
    if user["is_admin"]:
        return Path(f"/home/{slot}") if slot else Path("/")
    tgt = slot or user["slot"]
    if not tgt or (slot and slot != user["slot"]):
        raise HTTPException(403, "no home")
    return Path(f"/home/{tgt}")


def slot_port(slot: str) -> int | None:
    """Terminal port for a slot. Dynamic slots live in the `slots` registry;
    pre-declared config slots keep their legacy index-based port."""
    base = int(CFG.get("ttyd", {}).get("port_base", 7681))
    if slot == "root":
        return base - 1
    try:
        with closing(D.connect(DB)) as con:
            r = con.execute("SELECT port FROM slots WHERE slot=?",
                            (slot,)).fetchone()
        if r:
            return int(r["port"])
    except Exception:
        pass
    slots: list = CFG.get("slots", [])
    if slot in slots:
        return base + slots.index(slot)
    return None


def cmd_row(r) -> dict:
    return {"id": r["id"], "name": r["name"],
            "argv": json.loads(r["argv"]), "run_as": r["run_as"],
            "allowed": json.loads(r["allowed"]), "timeout_sec": r["timeout_sec"]}


UNIT_RE = re.compile(r"^[A-Za-z0-9@.:_-]+\.(service|socket|timer|target)$")
