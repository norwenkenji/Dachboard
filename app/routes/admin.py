import json
import time
from contextlib import closing
from fastapi import APIRouter, Cookie, Request
from .. import auth as A
from .. import db as D
from .. import deps as P
from ..rbac import ADMIN_ONLY, RIGHTS
from fastapi import HTTPException
import asyncio

router = APIRouter()
# ---------- api tokens (machine access for bots/sites/any code) ----------

@router.get("/api/tokens")
async def tokens_list(dach_sid: str | None = Cookie(default=None)):
    await P.require("users_manage", dach_sid)
    with closing(D.connect(P.DB)) as con:
        rows = con.execute(
            "SELECT id,name,rights,created_at,last_used_at FROM api_tokens ORDER BY id").fetchall()
    return [{**dict(r), "rights": D.jload(r["rights"], {})} for r in rows]


@router.post("/api/tokens")
async def tokens_create(request: Request, dach_sid: str | None = Cookie(default=None)):
    await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    name = str(body.get("name", "")).strip()[:64] or "bot"
    rights = {r: bool(body.get("rights", {}).get(r, False)) for r in RIGHTS
              if r not in ADMIN_ONLY}
    tok, digest = A.api_token()
    with closing(D.connect(P.DB)) as con:
        try:
            cur = con.execute(
                "INSERT INTO api_tokens(name,token_hash,rights,created_at)"
                " VALUES(?,?,?,?)",
                (name, digest, json.dumps(rights), int(time.time())))
            con.commit()
            return {"id": cur.lastrowid, "token": tok}
        except Exception as e:
            raise HTTPException(400, str(e))


@router.delete("/api/tokens/{tid}")
async def tokens_delete(tid: int, request: Request,
                        dach_sid: str | None = Cookie(default=None)):
    await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
    with closing(D.connect(P.DB)) as con:
        con.execute("DELETE FROM api_tokens WHERE id=?", (tid,))
        con.commit()
    return {"ok": True}


# ---------- users (admin) ----------

@router.get("/api/users")
async def users_list(dach_sid: str | None = Cookie(default=None)):
    await P.require("users_manage", dach_sid)
    with closing(D.connect(P.DB)) as con:
        rows = con.execute(
            "SELECT id,login,is_admin,rights,limits,slot,must_change_pw,created_at"
            " FROM users ORDER BY id").fetchall()
    return [{**dict(r), "is_admin": bool(r["is_admin"]),
             "rights": D.jload(r["rights"], {}), "limits": D.jload(r["limits"], {}),
             "must_change_pw": bool(r["must_change_pw"])}
            for r in rows]


@router.post("/api/users")
async def users_create(request: Request, dach_sid: str | None = Cookie(default=None)):
    await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
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
    with closing(D.connect(P.DB)) as con:
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


@router.put("/api/users/{uid}")
async def users_update(uid: int, request: Request,
                       dach_sid: str | None = Cookie(default=None)):
    me_ = await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    sets, vals = [], []
    if "login" in body:
        login = str(body["login"]).strip()
        if not login or len(login) > 32:
            raise HTTPException(400, "bad login")
        with closing(D.connect(P.DB)) as con:
            r = con.execute("SELECT id FROM users WHERE login=?", (login,)).fetchone()
            if r and r["id"] != uid:
                raise HTTPException(400, "login taken")
        sets.append("login=?")
        vals.append(login)
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
    with closing(D.connect(P.DB)) as con:
        con.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", (*vals, uid))
        con.commit()
        row = con.execute("SELECT slot, limits FROM users WHERE id=?", (uid,)).fetchone()
    quota_applied, quota_msg = False, ""
    if row and row["slot"]:
        from .. import quota as Q
        lim = D.jload(row["limits"], {}).get("disk_quota")
        quota_applied, quota_msg = await asyncio.to_thread(Q.apply_quota, row["slot"], lim)
    return {"ok": True, "quota_applied": quota_applied, "quota_msg": quota_msg}


@router.delete("/api/users/{uid}")
async def users_delete(uid: int, request: Request,
                       dach_sid: str | None = Cookie(default=None)):
    me_ = await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
    if uid == me_["id"]:
        raise HTTPException(400, "no self-delete")
    with closing(D.connect(P.DB)) as con:
        con.execute("DELETE FROM users WHERE id=?", (uid,))
        con.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        con.commit()
    return {"ok": True}


@router.get("/api/rights")
async def rights_list(dach_sid: str | None = Cookie(default=None)):
    await P.require("users_manage", dach_sid)
    from ..rbac import ADMIN_ONLY
    return {"rights": RIGHTS, "admin_only": sorted(ADMIN_ONLY)}
