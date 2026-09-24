import asyncio
import json
import time
from contextlib import closing

from fastapi import APIRouter, Cookie, HTTPException, Request

from .. import audit as AUDIT
from .. import auth as A
from .. import db as D
from .. import deps as P
from .. import security as SEC
from ..rbac import ADMIN_ONLY, RIGHTS, TOKEN_HOLDABLE

router = APIRouter()
# ---------- api tokens (machine access for bots/sites/any code) ----------

@router.get("/api/tokens")
async def tokens_list(dach_sid: str | None = Cookie(default=None)):
    await P.require("users_manage", dach_sid)
    with closing(D.connect(P.DB)) as con:
        rows = con.execute(
            "SELECT id,name,rights,slot,is_admin,created_at,last_used_at"
            " FROM api_tokens ORDER BY id").fetchall()
    return [{**dict(r), "rights": D.jload(r["rights"], {}),
             "is_admin": bool(r["is_admin"])} for r in rows]


@router.post("/api/tokens")
async def tokens_create(request: Request, dach_sid: str | None = Cookie(default=None)):
    me = await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    name = str(body.get("name", "")).strip()[:64] or "bot"
    holdable = {r for r in RIGHTS if r not in ADMIN_ONLY} | TOKEN_HOLDABLE
    rights = {r: bool(body.get("rights", {}).get(r, False)) for r in RIGHTS
              if r in holdable}
    slot = str(body.get("slot") or "").strip() or None
    if slot and not P.SLOT_RE.fullmatch(slot):
        raise HTTPException(400, "bad slot")
    is_adm = 1 if body.get("is_admin") else 0
    tok, digest = A.api_token()
    with closing(D.connect(P.DB)) as con:
        try:
            cur = con.execute(
                "INSERT INTO api_tokens(name,token_hash,rights,slot,is_admin,created_at)"
                " VALUES(?,?,?,?,?,?)",
                (name, digest, json.dumps(rights), slot, is_adm, int(time.time())))
            con.commit()
        except Exception as e:
            raise HTTPException(400, str(e)) from None
    # The token itself is never logged — only enough to find the row again.
    AUDIT.event("token_create", token_id=cur.lastrowid, token_name=name,
                token_admin=is_adm, token_slot=slot,
                granted=sorted(r for r, on in rights.items() if on) or "-",
                ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(me))
    return {"id": cur.lastrowid, "token": tok}


@router.delete("/api/tokens/{tid}")
async def tokens_delete(tid: int, request: Request,
                        dach_sid: str | None = Cookie(default=None)):
    me = await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
    with closing(D.connect(P.DB)) as con:
        con.execute("DELETE FROM api_tokens WHERE id=?", (tid,))
        con.commit()
    AUDIT.event("token_revoke", token_id=tid,
                ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(me))
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
    me = await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    login = str(body.get("login", "")).strip()
    if not login or len(login) > 32:
        raise HTTPException(400, "bad login")
    password = str(body.get("password") or "")
    if len(password) < 8:
        raise HTTPException(400, "password min 8")
    rights = {r: bool(body.get("rights", {}).get(r, False)) for r in RIGHTS}
    is_adm = bool(body.get("is_admin"))
    if is_adm:
        rights = dict.fromkeys(RIGHTS, True)
    slot = str(body.get("slot") or "").strip().lower() or None
    ip = SEC.client_ip(request, P.CFG)
    slot_log = []
    if slot:
        from .. import provision as PR
        known = set(PR.registered_slots(P.DB))
        with closing(D.connect(P.DB)) as con:
            known |= {r["slot"] for r in con.execute(
                "SELECT slot FROM users WHERE slot IS NOT NULL")}
        err = PR.name_error(slot, known)
        if err:
            raise HTTPException(400, f"slot: {err}")
        # daemon runs as root, so a brand-new slot is built on demand
        res = await asyncio.to_thread(PR.create_slot, P.DB, slot,
                                      (P.CFG.get("defaults") or {}).get("disk_quota"))
        if not res.get("ok"):
            AUDIT.event("slot_provision_failed", slot=slot,
                        reason=res.get("msg", "")[:200], ip=ip,
                        **AUDIT.actor(me))
            raise HTTPException(400, res.get("msg", "slot provisioning failed"))
        slot_log = res.get("log", [])
        AUDIT.event("slot_provision", slot=slot, port=res.get("port"), ip=ip,
                    **AUDIT.actor(me))
    with closing(D.connect(P.DB)) as con:
        try:
            cur = con.execute(
                "INSERT INTO users(login,pass_hash,is_admin,rights,limits,slot,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (login, A.hash_password(password), 1 if is_adm else 0,
                 json.dumps(rights), json.dumps(body.get("limits", {})),
                 slot, int(time.time())))
            con.commit()
        except Exception as e:
            raise HTTPException(400, str(e)) from None
    # Creating an admin is the single most consequential act in the panel.
    AUDIT.event("user_create", target=login, target_id=cur.lastrowid,
                target_admin=int(is_adm), target_slot=slot,
                granted=sorted(r for r, on in rights.items() if on) or "-",
                ip=ip, **AUDIT.actor(me))
    return {"id": cur.lastrowid, "slot_log": slot_log}


@router.put("/api/users/{uid}")
async def users_update(uid: int, request: Request,
                       dach_sid: str | None = Cookie(default=None)):
    me_ = await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    # `vals` is deliberately heterogeneous: a SET clause takes login strings,
    # rights JSON, and the 0/1 integers that back SQLite booleans alike.
    sets: list[str] = []
    vals: list[object] = []
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
        newslot = str(body.get("slot") or "").strip().lower() or None
        if newslot:
            from .. import provision as PR
            known = set(PR.registered_slots(P.DB))
            with closing(D.connect(P.DB)) as con:
                known |= {r["slot"] for r in con.execute(
                    "SELECT slot FROM users WHERE slot IS NOT NULL")}
            err = PR.name_error(newslot, known)
            if err:
                raise HTTPException(400, f"slot: {err}")
            res = await asyncio.to_thread(PR.create_slot, P.DB, newslot,
                                          (P.CFG.get("defaults") or {}).get("disk_quota"))
            if not res.get("ok"):
                raise HTTPException(400, res.get("msg", "slot provisioning failed"))
        sets.append("slot=?")
        vals.append(newslot)
    if body.get("password"):
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
            vals.append(json.dumps(dict.fromkeys(RIGHTS, True)))
    if not sets:
        return {"ok": True}
    with closing(D.connect(P.DB)) as con:
        before = con.execute(
            "SELECT login, is_admin, rights, slot FROM users WHERE id=?",
            (uid,)).fetchone()
        con.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", (*vals, uid))
        con.commit()
        row = con.execute("SELECT slot, limits FROM users WHERE id=?", (uid,)).fetchone()
    AUDIT.event("user_update", target_id=uid,
                target=before["login"] if before else "-",
                changed=sorted(_changed_fields(body)),
                was_admin=int(before["is_admin"]) if before else "-",
                now_admin=1 if body.get("is_admin") else (
                    int(before["is_admin"]) if before else 0),
                now_slot=body.get("slot", "-"),
                granted=sorted(r for r, on in
                               (body.get("rights") or {}).items() if on) or None,
                password_reset=bool(body.get("password")),
                ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(me_))
    quota_applied, quota_msg = False, ""
    if row and row["slot"]:
        from .. import quota as Q
        lim = D.jload(row["limits"], {}).get("disk_quota")
        quota_applied, quota_msg = await asyncio.to_thread(Q.apply_quota, row["slot"], lim)
    return {"ok": True, "quota_applied": quota_applied, "quota_msg": quota_msg}


#: Which request fields an update may carry, for the audit trail. Passwords and
#: hashes are deliberately not in this list — only the fact of a reset is.
_UPDATABLE = ("login", "rights", "limits", "slot", "password", "must_change_pw",
              "is_admin")


def _changed_fields(body: dict):
    for k in _UPDATABLE:
        if k in body:
            yield k


@router.delete("/api/users/{uid}")
async def users_delete(uid: int, request: Request,
                       dach_sid: str | None = Cookie(default=None)):
    me_ = await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
    if uid == me_["id"]:
        raise HTTPException(400, "no self-delete")
    with closing(D.connect(P.DB)) as con:
        row = con.execute("SELECT login, is_admin, slot FROM users WHERE id=?",
                          (uid,)).fetchone()
        con.execute("DELETE FROM users WHERE id=?", (uid,))
        con.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        con.commit()
    AUDIT.event("user_delete", target_id=uid,
                target=row["login"] if row else "-",
                was_admin=int(row["is_admin"]) if row else "-",
                target_slot=row["slot"] if row else None,
                ip=SEC.client_ip(request, P.CFG), **AUDIT.actor(me_))
    return {"ok": True}


@router.get("/api/rights")
async def rights_list(dach_sid: str | None = Cookie(default=None)):
    await P.require("users_manage", dach_sid)
    return {"rights": RIGHTS, "admin_only": sorted(ADMIN_ONLY)}


@router.get("/api/slots")
async def slots_list(dach_sid: str | None = Cookie(default=None)):
    await P.require("users_manage", dach_sid)
    rows = []
    with closing(D.connect(P.DB)) as con:
        for r in con.execute("SELECT slot, port, created_at FROM slots ORDER BY slot"):
            rows.append(dict(r))
    return {"slots": rows, "legacy": list(P.CFG.get("slots") or [])}


@router.post("/api/slots")
async def slots_create(request: Request, dach_sid: str | None = Cookie(default=None)):
    """Provision a brand-new slot by name (linux user + home + quota + ttyd +
    nginx gate). The daemon runs as root, so this builds it for real."""
    me = await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json()
    slot = str(body.get("slot", "")).strip().lower()
    ip = SEC.client_ip(request, P.CFG)
    from .. import provision as PR
    err = PR.name_error(slot, set(PR.registered_slots(P.DB)))
    if err:
        AUDIT.event("slot_provision_denied", slot=slot, reason=err[:200], ip=ip,
                    **AUDIT.actor(me))
        raise HTTPException(400, f"slot: {err}")
    res = await asyncio.to_thread(
        PR.create_slot, P.DB, slot,
        (P.CFG.get("defaults") or {}).get("disk_quota"))
    if not res.get("ok"):
        AUDIT.event("slot_provision_failed", slot=slot,
                    reason=str(res.get("msg", ""))[:200], ip=ip,
                    **AUDIT.actor(me))
        raise HTTPException(400, res.get("msg", "slot provisioning failed"))
    AUDIT.event("slot_provision", slot=slot, port=res.get("port"), ip=ip,
                **AUDIT.actor(me))
    return {"ok": True, "slot": slot, "port": res.get("port"),
            "log": res.get("log", [])}


@router.delete("/api/slots/{slot}")
async def slots_delete(slot: str, request: Request,
                       dach_sid: str | None = Cookie(default=None)):
    me = await P.require("users_manage", dach_sid)
    P.check_csrf(request, dach_sid)
    body = await request.json() if request.headers.get(
        "content-type", "").startswith("application/json") else {}
    wipe = bool(body.get("wipe"))
    ip = SEC.client_ip(request, P.CFG)
    with closing(D.connect(P.DB)) as con:
        if con.execute("SELECT 1 FROM users WHERE slot=?", (slot,)).fetchone():
            AUDIT.event("slot_wipe_denied", slot=slot, reason="still assigned",
                        ip=ip, **AUDIT.actor(me))
            raise HTTPException(400, "slot still assigned to a user")
    from .. import provision as PR
    res = await asyncio.to_thread(PR.remove_slot, P.DB, slot, wipe)
    if not res.get("ok"):
        AUDIT.event("slot_remove_failed", slot=slot, wipe=int(wipe),
                    reason=str(res.get("msg", ""))[:200], ip=ip,
                    **AUDIT.actor(me))
        raise HTTPException(400, res.get("msg", "slot removal failed"))
    # `wipe` runs `userdel -r`: the home directory is gone for good, so this is
    # the one event that must be reconstructible after the fact.
    AUDIT.event("slot_wipe" if wipe else "slot_remove", slot=slot,
                wipe=int(wipe), ip=ip, **AUDIT.actor(me))
    return {"ok": True, "log": res.get("log", [])}
