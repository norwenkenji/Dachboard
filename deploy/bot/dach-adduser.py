#!/usr/bin/env python3
"""Root-side helper for the Telegram bot: create/revoke a dashboard account
with a freshly provisioned slot (linux user + quota + ttyd + nginx gate).

Runs ONLY as the one-shot unit dach-adduser.service, because the dashboard DB
is root-owned and the bot (uid zxc) cannot write it or call useradd. The bot
writes req.json (0600), starts the unit, reads res.json.

Slots are dynamic: the admin names one, it is built on demand. The heavy
lifting (validation, linux user, ttyd, nginx) lives in app.provision so the
web UI and this bot share exactly one code path.

Guards:
  * slot name validated by app.provision (rejects reserved names and any
    pre-existing linux user that is not a dachboard slot);
  * rights are hardcoded to "everything except users_manage and commands_edit"
    -> a bot-created account is never an admin;
  * the request body cannot widen rights or target another user's slot.
"""
from __future__ import annotations

import json
import os
import re
import sys
from contextlib import closing
from pathlib import Path

try:
    import pwd
except ImportError:  # non-posix dev box: chown/chmod below are best-effort
    pwd = None  # type: ignore[assignment]

sys.path.insert(0, "/opt/dachboard")
from app import auth as A
from app import db as D
from app import deps as P
from app import provision as PR
from app.rbac import ADMIN_ONLY, RIGHTS

HERE = Path("/home/zxc/dach-adduser")
REQ = HERE / "req.json"
RES = HERE / "res.json"

LOGIN_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,31}$")


def done(ok: bool, msg: str, **extra) -> None:
    RES.write_text(json.dumps({"ok": ok, "msg": msg, **extra}))
    # Lock the mode FIRST, unconditionally. res.json carries the login of the
    # account just created, and the old order ran chmod inside the same try as
    # getpwnam/chown — so any failure in the chown path left the file at the
    # default 0644, readable by every local user. Tightening the mode cannot
    # depend on resolving zxc succeeding.
    try:
        os.chmod(RES, 0o600)
    except OSError as e:
        print(f"warning: cannot lock res.json to 0600: {e}")
    try:
        if pwd is None:
            raise RuntimeError("no pwd module on this platform")
        st = pwd.getpwnam("zxc")
        os.chown(RES, st.pw_uid, st.pw_gid)
    except Exception as e:
        print(f"warning: cannot hand res.json to zxc: {e}")
    print(("OK " if ok else "FAIL ") + msg)


def disk_quota() -> str | None:
    return (P.CFG.get("defaults") or {}).get("disk_quota")


def create(req: dict) -> None:
    login = str(req.get("login", "")).strip().lower()
    password = str(req.get("password", ""))
    slot = str(req.get("slot", "")).strip().lower()

    # Guards write the response and return; `done()` is a statement, not a
    # value, so each early exit is spelled out rather than smuggled through
    # `return done(...)`.
    if not LOGIN_RE.fullmatch(login):
        done(False, "bad login (start a-z0-9, then a-z0-9_- , 3..32)")
        return
    if len(password) < 8:
        done(False, "password min 8")
        return

    err = PR.name_error(slot, set(PR.registered_slots(P.DB)))
    if err:
        done(False, f"slot: {err}")
        return

    with closing(D.connect(P.DB)) as con:
        if con.execute("SELECT 1 FROM users WHERE login=?", (login,)).fetchone():
            done(False, f"login {login} already taken")
            return
        if con.execute("SELECT 1 FROM users WHERE slot=?", (slot,)).fetchone():
            done(False, f"slot {slot} already assigned to another user")
            return

    r = PR.create_slot(P.DB, slot, disk_quota())
    if not r.get("ok"):
        done(False, r.get("msg", "slot creation failed"), log=r.get("log"))
        return

    rights = {x: (x not in ADMIN_ONLY) for x in RIGHTS}
    limits = dict(P.CFG.get("defaults") or {})
    import time
    with closing(D.connect(P.DB)) as con:
        cur = con.execute(
            "INSERT INTO users(login,pass_hash,is_admin,rights,limits,slot,"
            "must_change_pw,created_at) VALUES(?,?,?,?,?,?,1,?)",
            (login, A.hash_password(password), 0, json.dumps(rights),
             json.dumps(limits), slot, int(time.time())))
        con.commit()
    log = list(r.get("log", []))
    log.append(f"dashboard user #{cur.lastrowid} {login} -> slot {slot}")
    done(True, "; ".join(log), login=login, slot=slot,
         port=r.get("port"), uid=cur.lastrowid, log=log)


def revoke(req: dict) -> None:
    login = str(req.get("login", "")).strip().lower()
    wipe = bool(req.get("wipe"))
    with closing(D.connect(P.DB)) as con:
        r = con.execute("SELECT id, slot, is_admin FROM users WHERE login=?",
                        (login,)).fetchone()
        if not r:
            done(False, f"no dashboard user {login}")
            return
        if r["is_admin"]:
            done(False, "refusing to touch an admin account")
            return
        con.execute("DELETE FROM sessions WHERE user_id=?", (r["id"],))
        con.execute("DELETE FROM api_tokens WHERE slot=?", (r["slot"],))
        con.execute("DELETE FROM users WHERE id=?", (r["id"],))
        con.commit()
    log = [f"dashboard user {login} deleted, sessions revoked"]
    if r["slot"]:
        rr = PR.remove_slot(P.DB, r["slot"], wipe=wipe)
        log += rr.get("log", [])
    done(True, "; ".join(log), log=log)


def wipe_slot(req: dict) -> None:
    """Delete a slot's data by name — for slots left behind by a revoke
    without wipe, where there is no dashboard login to look up anymore."""
    slot = str(req.get("slot", "")).strip().lower()
    if slot not in PR.registered_slots(P.DB):
        done(False, f"no such slot {slot!r}")
        return
    with closing(D.connect(P.DB)) as con:
        if con.execute("SELECT 1 FROM users WHERE slot=?", (slot,)).fetchone():
            done(False, f"slot {slot} is still assigned to a user")
            return
    r = PR.remove_slot(P.DB, slot, wipe=True)
    done(bool(r.get("ok")), r.get("msg", "wipe failed"), log=r.get("log"))


def main() -> None:
    try:
        req = json.loads(REQ.read_text())
    except Exception as e:
        return done(False, f"cannot read req.json: {e}")
    finally:
        REQ.unlink(missing_ok=True)             # never leave creds on disk
    op = str(req.get("op", "create"))
    try:
        if op == "revoke":
            revoke(req)
        elif op == "wipe_slot":
            wipe_slot(req)
        else:
            create(req)
    except Exception as e:
        done(False, f"crash: {e}")


if __name__ == "__main__":
    main()
