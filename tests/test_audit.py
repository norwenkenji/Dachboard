"""Audit trail and login throttling.

The audit logger sets ``propagate = False`` (it must reach the journal on its
own, not via the root logger), so pytest's ``caplog`` — which hangs off root —
never sees it. These tests attach their own handler instead, which also pins
that real behavior rather than a testing convenience.
"""
import json
import logging
from typing import ClassVar

import pytest
from conftest import login

from app import audit as AUDIT
from app import deps as P
from app import security as SEC


@pytest.fixture()
def audit_records():
    """Capture audit records for one test, leaving the logger as it was."""
    log = logging.getLogger(AUDIT.LOGGER_NAME)
    saved_handlers, saved_propagate = list(log.handlers), log.propagate

    records = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    h = _Capture()
    h.setFormatter(AUDIT._Formatter())
    log.handlers = [h]
    log.setLevel(logging.INFO)
    try:
        yield records
    finally:
        log.handlers = saved_handlers
        log.propagate = saved_propagate


def _events(records):
    """Rendered audit lines, as key=value text."""
    return [AUDIT._Formatter().format(r) for r in records]


def _fields(records, event):
    """The parsed fields of every record named ``event``."""
    out = []
    for r in records:
        if r.getMessage() != event:
            continue
        out.append(getattr(r, "audit", {}) or {})
    return out


# ---------- what gets recorded ----------

def test_login_is_audited(clients, audit_records):
    login(clients["bob"], "bob")
    got = _fields(audit_records, "login")
    assert len(got) == 1
    assert got[0]["actor"] == "bob"
    assert "ip" in got[0]


def test_failed_login_is_audited_with_the_attempt_count(clients, audit_records):
    clients["bob"].post("/api/login",
                        json={"login": "bob", "password": "wrong"})
    got = _fields(audit_records, "login_failed")
    assert len(got) == 1
    assert got[0]["attempted"] == "bob"
    assert got[0]["fails"] == 1
    # the password itself must never appear anywhere in the trail
    assert "wrong" not in "".join(_events(audit_records))


def test_no_password_or_token_reaches_the_trail(clients, audit_records):
    login(clients["bob"], "bob")
    clients["bob"].post("/api/login",
                        json={"login": "bob", "password": "s3cr3t-value"})
    text = "".join(_events(audit_records))
    assert "s3cr3t-value" not in text
    assert "pass-" not in text


def test_denial_is_audited(clients, audit_records):
    """A 403 on a privileged action is the signal worth alerting on."""
    bcsrf = login(clients["bob"], "bob")
    r = clients["bob"].post("/api/services/cron.service/stop",
                            headers={"X-CSRF-Token": bcsrf})
    assert r.status_code == 403
    got = _fields(audit_records, "denied")
    assert got and got[-1]["right"] == "services_control"
    assert got[-1]["actor"] == "bob"


def test_csrf_rejection_is_audited(clients, audit_records):
    login(clients["bob"], "bob")
    r = clients["bob"].post("/api/files/write",
                            json={"path": "x", "content": "y"},
                            headers={"X-CSRF-Token": "not-the-token"})
    assert r.status_code == 403
    got = _fields(audit_records, "csrf_rejected")
    assert len(got) == 1
    assert got[0]["path"] == "/api/files/write"


def test_service_action_is_audited(clients, audit_records):
    acsrf = login(clients["admin"], "admin")
    r = clients["admin"].post("/api/services/cron.service/restart",
                              headers={"X-CSRF-Token": acsrf})
    assert r.status_code == 200
    got = _fields(audit_records, "service_action")
    assert len(got) == 1
    assert got[0]["unit"] == "cron.service"
    assert got[0]["action"] == "restart"
    assert "exit" in got[0]


def test_service_logs_read_is_audited(clients, audit_records):
    """Reading a journal exposes host secrets, so who looked is recorded."""
    login(clients["admin"], "admin")
    clients["admin"].get("/api/services/cron.service/logs")
    got = _fields(audit_records, "service_logs")
    assert len(got) == 1
    assert got[0]["unit"] == "cron.service"


def test_user_crud_is_audited(clients, audit_records):
    acsrf = login(clients["admin"], "admin")
    h = {"X-CSRF-Token": acsrf, "Content-Type": "application/json"}
    r = clients["admin"].post("/api/users", json={
        "login": "carol", "password": "longenough1", "is_admin": False,
        "rights": {"files": True}}, headers=h)
    assert r.status_code == 200, r.text
    new_id = r.json()["id"]
    created = _fields(audit_records, "user_create")
    assert len(created) == 1
    assert created[0]["target"] == "carol"
    assert created[0]["target_admin"] == 0
    assert "files" in str(created[0]["granted"])

    clients["admin"].put(f"/api/users/{new_id}",
                         json={"rights": {"files": True, "terminal": True}},
                         headers=h)
    updated = _fields(audit_records, "user_update")
    assert len(updated) == 1
    assert "rights" in str(updated[0]["changed"])

    clients["admin"].delete(f"/api/users/{new_id}", headers=h)
    deleted = _fields(audit_records, "user_delete")
    assert len(deleted) == 1
    assert deleted[0]["target"] == "carol"


def test_privilege_escalation_shows_the_admin_flip(clients, audit_records):
    acsrf = login(clients["admin"], "admin")
    h = {"X-CSRF-Token": acsrf, "Content-Type": "application/json"}
    r = clients["admin"].post("/api/users", json={
        "login": "dave", "password": "longenough1"}, headers=h)
    uid = r.json()["id"]
    clients["admin"].put(f"/api/users/{uid}", json={"is_admin": True}, headers=h)
    updated = _fields(audit_records, "user_update")[-1]
    assert updated["was_admin"] == 0
    assert updated["now_admin"] == 1


def test_token_lifecycle_is_audited_without_the_secret(clients, audit_records):
    acsrf = login(clients["admin"], "admin")
    h = {"X-CSRF-Token": acsrf, "Content-Type": "application/json"}
    r = clients["admin"].post("/api/tokens",
                              json={"name": "ci-bot", "is_admin": False},
                              headers=h)
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    created = _fields(audit_records, "token_create")
    assert len(created) == 1
    assert created[0]["token_name"] == "ci-bot"
    # the minted secret must not be recoverable from the log
    text = "".join(_events(audit_records))
    assert token not in text
    assert token.split("_", 1)[1] not in text

    clients["admin"].delete(f"/api/tokens/{r.json()['id']}", headers=h)
    revoked = _fields(audit_records, "token_revoke")
    assert len(revoked) == 1
    assert revoked[0]["token_id"] == r.json()["id"]


def test_password_change_is_audited(clients, audit_records):
    csrf = login(clients["bob"], "bob")
    r = clients["bob"].post("/api/me/password", json={
        "old_password": "pass-bob", "new_password": "brandnewpass1"},
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    got = _fields(audit_records, "password_change")
    assert len(got) == 1
    assert got[0]["actor"] == "bob"
    assert "brandnewpass1" not in "".join(_events(audit_records))


def test_own_home_file_write_is_not_audited(clients, audit_records):
    """Routine slot activity stays out of the trail — or it is all noise.

    A slot user with the terminal right can write their own home from a shell
    without any log line, so auditing the API path for it would imply a
    completeness that does not exist.
    """
    csrf = login(clients["bob"], "bob")
    h = {"X-CSRF-Token": csrf, "Content-Type": "application/json"}
    r = clients["bob"].post("/api/files/write",
                            json={"path": "note.txt", "content": "hi"},
                            headers=h)
    assert r.status_code == 200
    assert not _fields(audit_records, "file_write")


def test_file_delete_is_audited(clients, audit_records):
    csrf = login(clients["bob"], "bob")
    h = {"X-CSRF-Token": csrf, "Content-Type": "application/json"}
    clients["bob"].post("/api/files/write",
                        json={"path": "gone.txt", "content": "x"}, headers=h)
    r = clients["bob"].post("/api/files/delete", json={"path": "gone.txt"},
                            headers=h)
    assert r.status_code == 200
    got = _fields(audit_records, "file_delete")
    assert len(got) == 1
    assert got[0]["path"] == "gone.txt"
    assert got[0]["actor"] == "bob"


def test_admin_cross_slot_access_is_audited(clients, audit_records):
    """An admin acting inside someone else's home is the exfil/plant vector."""
    acsrf = login(clients["admin"], "admin")
    h = {"X-CSRF-Token": acsrf, "Content-Type": "application/json"}
    r = clients["admin"].post("/api/files/write",
                              json={"path": "planted.txt", "content": "x",
                                    "slot": "u-bob"}, headers=h)
    assert r.status_code == 200, r.text
    got = _fields(audit_records, "file_write")
    assert len(got) == 1
    assert got[0]["target_slot"] == "u-bob"


def test_audit_never_breaks_a_request(clients, monkeypatch):
    """A broken audit sink must not take the panel down with it.

    The sink is what fails in practice — a full disk, a rotated-away file, a
    dead journal socket. Patching ``event`` itself would only test the test, so
    the handler's ``emit`` is the thing replaced here.
    """
    log = logging.getLogger(AUDIT.LOGGER_NAME)

    class _Boom(logging.Handler):
        def emit(self, record):
            raise RuntimeError("audit sink is on fire")

    boom = _Boom()
    saved = list(log.handlers)
    log.handlers = [boom]
    try:
        # login audits internally; the route must still answer 200
        csrf = login(clients["bob"], "bob")
        assert csrf
        r = clients["bob"].get("/api/me")
        assert r.status_code == 200
    finally:
        log.handlers = saved


def test_audit_never_breaks_a_request_when_formatting_fails(
        clients, monkeypatch):
    """A failure *inside* ``event()`` must not propagate either.

    ``StreamHandler.emit`` swallows formatter errors via ``handleError``, so it
    cannot demonstrate this. A handler that formats in ``emit`` can:
    ``Handler.handle`` deliberately lets that exception out, so it travels back
    through ``log.info`` into ``event()``'s guard. Patching ``_scalar`` then
    proves the try/except really covers the formatting path.
    """
    log = logging.getLogger(AUDIT.LOGGER_NAME)

    class _Propagating(logging.Handler):
        def emit(self, record):
            AUDIT._Formatter().format(record)

    saved = list(log.handlers)
    log.handlers = [_Propagating()]
    monkeypatch.setattr(AUDIT, "_scalar",
                        lambda v: (_ for _ in ()).throw(RuntimeError("boom")))
    try:
        assert login(clients["bob"], "bob")
        assert clients["bob"].get("/api/me").status_code == 200
    finally:
        log.handlers = saved


def test_actor_keys_cannot_collide_with_call_sites():
    """Guards the TypeError that would otherwise abort an audited request.

    ``**AUDIT.actor(u)`` is expanded at the call site, so a bare ``slot`` key
    collides with a caller's own ``slot=`` argument *before* ``event()`` runs —
    its internal try/except can never see it. Prefixing is the only fix.
    """
    a = AUDIT.actor({"login": "bob", "is_admin": False, "slot": "u-bob"})
    assert set(a) == {"actor", "actor_slot"}, a
    adm = AUDIT.actor({"login": "root", "is_admin": True, "via": "token"})
    assert "actor_admin" in adm and adm["actor_via"] == "token"
    # and the collision that used to happen no longer does
    AUDIT.event("x", slot="u-bob", unit="cron.service", **a)


def test_formatter_quotes_values_with_spaces():
    rec = logging.LogRecord("dachboard.audit", logging.INFO, "f", 1,
                            "some_event", (), None)
    rec.audit = {"path": "my file.txt", "actor": "bob"}
    line = AUDIT._Formatter().format(rec)
    assert 'path="my file.txt"' in line
    assert "actor=bob" in line
    assert line.startswith("ts=")


def test_configure_is_idempotent():
    log = AUDIT.configure({})
    before = len(log.handlers)
    AUDIT.configure({})
    AUDIT.configure({})
    assert len(log.handlers) == before


def test_configure_survives_an_unwritable_audit_file(tmp_path):
    """A bad ``audit.file`` must degrade to the journal, never crash boot.

    A full disk or an unwritable path is a realistic failure, and it happens at
    startup — the panel has to come up anyway.
    """
    import app.audit as A2

    def raiser(*a, **k):
        raise OSError("disk full")

    real_file_handler = logging.FileHandler
    A2.logging.FileHandler = raiser
    saved = A2._configured
    saved_handlers = list(logging.getLogger(AUDIT.LOGGER_NAME).handlers)
    try:
        A2._configured = False
        logging.getLogger(AUDIT.LOGGER_NAME).handlers = []
        log = A2.configure({"audit": {"file": str(tmp_path / "audit.log")}})
        assert log.handlers, "the stderr/journal fallback must remain"
    finally:
        A2.logging.FileHandler = real_file_handler
        A2._configured = saved
        logging.getLogger(AUDIT.LOGGER_NAME).handlers = saved_handlers


def test_audit_file_handler_writes(tmp_path):
    """With ``audit.file`` configured the trail lands in that file too."""
    target = tmp_path / "audit" / "dachboard-audit.log"
    import app.audit as A2
    saved = A2._configured
    saved_handlers = list(logging.getLogger(AUDIT.LOGGER_NAME).handlers)
    try:
        A2._configured = False
        logging.getLogger(AUDIT.LOGGER_NAME).handlers = []
        log = A2.configure({"audit": {"file": str(target)}})
        AUDIT.event("unit_test_event", actor="probe")
        for h in log.handlers:
            h.flush()
        assert "unit_test_event" in target.read_text(encoding="utf-8")
        assert "actor=probe" in target.read_text(encoding="utf-8")
    finally:
        for h in logging.getLogger(AUDIT.LOGGER_NAME).handlers:
            h.close()
        logging.getLogger(AUDIT.LOGGER_NAME).handlers = saved_handlers
        A2._configured = saved


# ---------- login throttling ----------

def test_login_is_throttled_per_address(clients, monkeypatch):
    monkeypatch.setattr(P, "LOGIN_FAIL_MAX", 3)
    for _ in range(3):
        r = clients["bob"].post("/api/login",
                                json={"login": "bob", "password": "nope"})
        assert r.status_code == 401
    r = clients["bob"].post("/api/login",
                            json={"login": "bob", "password": "pass-bob"})
    assert r.status_code == 429, "the budget must be spent even on a good password"


def test_throttle_is_per_ip_not_global(clients, monkeypatch):
    """One attacker burning a bucket must not lock everyone else out."""
    monkeypatch.setattr(P, "LOGIN_FAIL_MAX", 2)
    for ip in ("1.2.3.4", "1.2.3.4"):
        clients["bob"].post("/api/login", json={"login": "bob",
                                                "password": "nope"},
                            headers={"X-Forwarded-For": ip})
    # the exhausted address is blocked
    r = clients["bob"].post("/api/login",
                            json={"login": "bob", "password": "pass-bob"},
                            headers={"X-Forwarded-For": "1.2.3.4"})
    assert r.status_code == 429
    # ...and a different one is untouched
    r = clients["bob"].post("/api/login",
                            json={"login": "bob", "password": "pass-bob"},
                            headers={"X-Forwarded-For": "9.9.9.9"})
    assert r.status_code == 200, r.text


def test_successful_login_clears_the_bucket(clients, monkeypatch):
    monkeypatch.setattr(P, "LOGIN_FAIL_MAX", 5)
    for _ in range(4):
        clients["bob"].post("/api/login",
                            json={"login": "bob", "password": "nope"})
    r = clients["bob"].post("/api/login",
                            json={"login": "bob", "password": "pass-bob"})
    assert r.status_code == 200
    # a fresh failure now starts from zero, not from 4
    clients["bob"].post("/api/login", json={"login": "bob", "password": "nope"})
    assert len(P.LOGIN_FAILS.get("testclient", [])) == 1


def test_throttle_window_expires(clients, monkeypatch):
    monkeypatch.setattr(P, "LOGIN_FAIL_MAX", 2)
    P.LOGIN_FAILS["testclient"] = [0.0, 0.0]      # ancient failures
    r = clients["bob"].post("/api/login",
                            json={"login": "bob", "password": "pass-bob"})
    assert r.status_code == 200, "stale failures must not block"


def test_failure_bucket_is_bounded(monkeypatch):
    """Months of spoofed addresses must not grow the dict without limit."""
    monkeypatch.setattr(P, "LOGIN_FAIL_MAX_KEYS", 16)
    P.LOGIN_FAILS.clear()
    for i in range(200):
        P.note_login_failure(f"10.0.{i // 256}.{i % 256}")
    assert len(P.LOGIN_FAILS) <= 16, len(P.LOGIN_FAILS)


def test_stale_entries_are_dropped_on_write(monkeypatch):
    monkeypatch.setattr(P, "LOGIN_FAIL_WINDOW", 60)
    P.LOGIN_FAILS["old"] = [0.0, 1.0]
    n = P.note_login_failure("old")
    assert n == 1, "only the fresh failure should survive the window"


# ---------- client address resolution ----------

class _FakeRequest:
    def __init__(self, headers, client_host="127.0.0.1"):
        self.headers = headers
        self.client = type("C", (), {"host": client_host})()


def test_client_ip_without_forwarded_header():
    req = _FakeRequest({})
    assert SEC.client_ip(req) == "127.0.0.1"


def test_client_ip_trusts_the_proxy_appended_hop():
    req = _FakeRequest({"x-forwarded-for": "203.0.113.7"})
    assert SEC.client_ip(req) == "203.0.113.7"


def test_client_ip_takes_the_rightmost_of_n_hops():
    """With a tunnel in front of nginx, only the proxy-written entries count."""
    req = _FakeRequest({"x-forwarded-for": "198.51.100.9, 203.0.113.7"})
    assert SEC.client_ip(req, {"forwarded_hops": 2}) == "198.51.100.9"
    assert SEC.client_ip(req, {"forwarded_hops": 1}) == "203.0.113.7"


def test_client_ip_cannot_be_spoofed_by_extra_entries():
    """An attacker prepends junk; the rightmost N entries still win."""
    req = _FakeRequest({"x-forwarded-for": "8.8.8.8, 1.1.1.1, 203.0.113.7"})
    assert SEC.client_ip(req, {"forwarded_hops": 1}) == "203.0.113.7"


def test_client_ip_rejects_garbage():
    for bad in ("not-an-ip", "1.2.3.4;DROP", "<script>", "", " "):
        req = _FakeRequest({"x-forwarded-for": bad})
        assert SEC.client_ip(req) == "127.0.0.1", bad


def test_client_ip_can_be_disabled():
    req = _FakeRequest({"x-forwarded-for": "203.0.113.7"})
    assert SEC.client_ip(req, {"trust_forwarded_for": False}) == "127.0.0.1"


def test_client_ip_handles_bracketed_ipv6():
    req = _FakeRequest({"x-forwarded-for": "[2001:db8::1]:5555"})
    assert SEC.client_ip(req) == "2001:db8::1"


def test_client_ip_no_client_object():
    class R:
        headers: ClassVar[dict] = {}
        client: ClassVar[None] = None
    assert SEC.client_ip(R()) == "?"


# ---------- session garbage collection ----------

def test_expired_sessions_are_pruned(env):
    import time as _time
    from contextlib import closing

    from app import db as D
    with closing(D.connect(env["db"])) as con:
        con.execute("INSERT INTO sessions(token,user_id,csrf,expires_at,created_at)"
                    " VALUES('dead',1,'c',?,?)",
                    (int(_time.time()) - 10, int(_time.time()) - 9999))
        con.execute("INSERT INTO sessions(token,user_id,csrf,expires_at,created_at)"
                    " VALUES('live',1,'c',?,?)",
                    (int(_time.time()) + 3600, int(_time.time())))
        con.commit()
    assert D.prune_sessions(env["db"]) == 1
    with closing(D.connect(env["db"])) as con:
        left = [r["token"] for r in con.execute("SELECT token FROM sessions")]
    assert left == ["live"]


def test_prune_sessions_is_a_noop_when_clean(env):
    from app import db as D
    assert D.prune_sessions(env["db"]) == 0


def test_rights_migration_is_not_needed_for_new_services_rights(env):
    """Existing users simply lack the new keys, so they lose host-systemd access.

    That is the intended default: an upgrade must never silently grant a
    non-admin root systemctl. Admins bypass RBAC entirely, so they keep working.
    """
    from app.rbac import RIGHTS, can
    assert "services_control" in RIGHTS
    legacy = {"overview": True, "containers_view": True,
              "containers_control": True}
    assert not can({"is_admin": False, "rights": legacy}, "services_control")
    assert can({"is_admin": False, "rights": legacy}, "containers_control")
    assert can({"is_admin": True, "rights": {}}, "services_control")
    # the stored JSON need not even mention the key
    assert json.dumps(legacy)
