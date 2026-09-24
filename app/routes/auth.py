import json
import secrets
import time
from contextlib import closing, suppress

from fastapi import APIRouter, Cookie, HTTPException, Request, Response

from .. import audit as AUDIT
from .. import auth as A
from .. import db as D
from .. import deps as P
from .. import security as SEC
from ..rbac import RIGHTS, can

router = APIRouter()
# ---------- auth ----------

@router.get("/api/setup-needed")
async def setup_needed():
    return {"needed": not P.admin_exists()}


@router.post("/api/setup")
async def setup(request: Request):
    """One-time bootstrap: create first admin. Burns the token file."""
    if P.admin_exists():
        raise HTTPException(404, "already set up")
    body = await request.json()
    p = P.setup_token_path()
    try:
        want = p.read_text().strip()
    except OSError:
        want = ""
    got = str(body.get("token", ""))
    ip = SEC.client_ip(request, P.CFG)
    if not want or not secrets.compare_digest(got, want):
        # Someone is guessing at the bootstrap token from the network.
        AUDIT.event("setup_denied", ip=ip)
        raise HTTPException(403, "bad token")
    login = str(body.get("login", "")).strip()
    password = str(body.get("password", ""))
    if not login or len(login) > 32 or len(password) < 12:
        raise HTTPException(400, "login required, password min 12")
    with closing(D.connect(P.DB)) as con:
        con.execute(
            "INSERT INTO users(login,pass_hash,is_admin,rights,limits,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (login, A.hash_password(password), 1,
             json.dumps(dict.fromkeys(RIGHTS, True)), "{}", int(time.time())))
        con.commit()
    with suppress(OSError):
        p.unlink()
    AUDIT.event("setup", actor=login, ip=ip)
    return {"ok": True}


@router.post("/api/login")
async def login(request: Request, response: Response):
    body = await request.json()
    # Behind nginx the socket peer is always the proxy, so the bucket key has to
    # come from the forwarded chain — otherwise every visitor shares one bucket
    # and ten stray failures lock the whole panel out for ten minutes.
    ip = SEC.client_ip(request, P.CFG)
    login_name = str(body.get("login", ""))
    if P.login_blocked(ip):
        AUDIT.event("login_throttled", ip=ip, attempted=login_name)
        raise HTTPException(429, "slow down")
    u = P.get_user_by_login(login_name)
    if not u or not A.verify_password(str(body.get("password", "")), u["pass_hash"]):
        n = P.note_login_failure(ip)
        AUDIT.event("login_failed", ip=ip, attempted=login_name, fails=n)
        raise HTTPException(401, "bad credentials")
    if u.get("must_change_pw"):
        AUDIT.event("login_must_change_pw", ip=ip, **AUDIT.actor(u))
        raise HTTPException(401, {"must_change": True})
    P.clear_login_failures(ip)
    tok, csrf = A.new_token(), A.new_token(16)
    ttl = int(P.CFG.get("session_ttl_hours", 72)) * 3600
    with closing(D.connect(P.DB)) as con:
        con.execute("INSERT INTO sessions(token,user_id,csrf,expires_at,created_at)"
                    " VALUES(?,?,?,?,?)",
                    (tok, u["id"], csrf, int(time.time()) + ttl, int(time.time())))
        con.commit()
    response.set_cookie(P.COOKIE, tok, httponly=True,
                        secure=bool(P.CFG.get("cookie_secure", True)),
                        samesite="lax", path="/", max_age=ttl)
    AUDIT.event("login", ip=ip, **AUDIT.actor(u))
    return {"csrf": csrf, "user": {k: v for k, v in u.items() if k != "pass_hash"}}


@router.post("/api/logout")
async def logout(request: Request, response: Response,
                 dach_sid: str | None = Cookie(default=None)):
    P.check_csrf(request, dach_sid)
    u = await P.session_user(dach_sid)
    if dach_sid:
        with closing(D.connect(P.DB)) as con:
            con.execute("DELETE FROM sessions WHERE token=?", (dach_sid,))
            con.commit()
    response.delete_cookie(P.COOKIE, path="/")
    AUDIT.event("logout", ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(u))
    return {"ok": True}


@router.get("/api/me")
async def me(request: Request, dach_sid: str | None = Cookie(default=None)):
    t = P.token_subject(request)
    if t:
        return t
    u = await P.session_user(dach_sid)
    if not u:
        raise HTTPException(401, "no session")
    return u


@router.get("/api/csrf")
async def csrf(dach_sid: str | None = Cookie(default=None)):
    """Restore CSRF token after page reload (session cookie survives, JS state doesn't)."""
    if not dach_sid:
        raise HTTPException(401, "no session")
    with closing(D.connect(P.DB)) as con:
        r = con.execute("SELECT csrf FROM sessions WHERE token=?", (dach_sid,)).fetchone()
        if not r:
            raise HTTPException(401, "no session")
        return {"csrf": r["csrf"]}


@router.post("/api/me/password")
async def me_password(request: Request, dach_sid: str | None = Cookie(default=None)):
    u = await P.session_user(dach_sid)
    if not u:
        raise HTTPException(401, "no session")
    P.check_csrf(request, dach_sid)
    body = await request.json()
    with closing(D.connect(P.DB)) as con:
        r = con.execute("SELECT pass_hash FROM users WHERE id=?", (u["id"],)).fetchone()
        if not r or not A.verify_password(str(body.get("old_password", "")), r["pass_hash"]):
            AUDIT.event("password_change_denied",
                        ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(u))
            raise HTTPException(401, "bad old password")
        new = str(body.get("new_password", ""))
        if len(new) < 8:
            raise HTTPException(400, "password min 8")
        con.execute("UPDATE users SET pass_hash=?, must_change_pw=0 WHERE id=?",
                    (A.hash_password(new), u["id"]))
        con.commit()
    AUDIT.event("password_change", ip=SEC.client_ip(request, P.CFG),
                **AUDIT.actor(u))
    return {"ok": True}


@router.post("/api/first-password")
async def first_password(request: Request):
    """Pre-registered user sets their own password on first login. No session."""
    body = await request.json()
    ip = SEC.client_ip(request, P.CFG)
    login_name = str(body.get("login", ""))
    u = P.get_user_by_login(login_name)
    new = str(body.get("new_password", ""))
    if (not u or not u.get("must_change_pw")
            or not A.verify_password(str(body.get("old_password", "")), u["pass_hash"])):
        n = P.note_login_failure(ip)
        AUDIT.event("first_password_denied", ip=ip, attempted=login_name, fails=n)
        raise HTTPException(401, "bad credentials")
    if len(new) < 8:
        raise HTTPException(400, "password min 8")
    with closing(D.connect(P.DB)) as con:
        con.execute("UPDATE users SET pass_hash=?, must_change_pw=0 WHERE id=?",
                    (A.hash_password(new), u["id"]))
        con.commit()
    AUDIT.event("first_password", ip=ip, **AUDIT.actor(u))
    return {"ok": True}


@router.get("/api/auth-check")
async def auth_check(request: Request, target: str = "", slot: str = "",
                     dach_sid: str | None = Cookie(default=None)):
    """nginx auth_request gate. 204 = pass. Slot comes via X-Slot header
    (per-slot auth locations) with query fallback for direct calls."""
    target = request.headers.get("x-target", "") or target
    slot = request.headers.get("x-slot", "") or slot
    u = await P.session_user(dach_sid)
    if not u:
        return Response(status_code=401)
    if target == "term":
        if not can(u, "terminal"):
            AUDIT.denied(u, "terminal", SEC.client_ip(request, P.CFG))
            return Response(status_code=403)
        if not u["is_admin"] and slot and slot != (u["slot"] or ""):
            # A terminal is a root-adjacent surface: probing for someone else's
            # slot is exactly what an audit trail needs to show.
            AUDIT.event("terminal_foreign_slot_denied", want=slot,
                        ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(u))
            return Response(status_code=403)
    return Response(status_code=204)

