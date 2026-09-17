"""Guards in deploy/bot/dach-adduser.py: the Telegram bot can only ever ask
root for a non-admin account with a valid, non-reserved slot name. Slot name
rules and the registry live in app/provision.py (tested in test_provision.py)."""
import importlib.util
import json
import pathlib

import pytest

from app.rbac import ADMIN_ONLY, RIGHTS

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "bot" / "dach-adduser.py"


@pytest.fixture(scope="module")
def helper():
    spec = importlib.util.spec_from_file_location("dach_adduser", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def scratch_files(helper, tmp_path, monkeypatch):
    """REQ/RES live in /home/zxc on the server; tests must not touch it."""
    monkeypatch.setattr(helper, "REQ", tmp_path / "req.json")
    monkeypatch.setattr(helper, "RES", tmp_path / "res.json")
    return tmp_path


def result(helper) -> dict:
    return json.loads(helper.RES.read_text())


def test_script_exists():
    assert SCRIPT.is_file(), "dach-adduser.py missing — the bot cannot provision"


def test_script_delegates_provisioning_to_app(helper):
    """One code path for UI and bot: no duplicate useradd/nginx logic here."""
    import re as _re
    src = SCRIPT.read_text(encoding="utf-8")
    assert "from app import provision" in src
    assert "PR.create_slot(" in src and "PR.remove_slot(" in src
    # no raw system commands: provisioning lives in app/provision.py only
    for cmd in ("useradd", "userdel", "nginx", "setquota", "systemctl"):
        assert not _re.search(r'["\']' + cmd + r'["\']', src), \
            f"{cmd} should be called via app.provision, not here"


@pytest.mark.parametrize("bad", [
    "../etc", "..", "/etc/passwd", "a b", "A", "ab", "x" * 33,
    "motya;rm", "motya`id`", "motya$(id)", "motya|id", "u-c4\nid",
    "motya'or", "-rf", "--help", "-u", "-",
])
def test_login_reject(helper, bad):
    assert not helper.LOGIN_RE.fullmatch(bad), f"login regex accepted {bad!r}"


@pytest.mark.parametrize("good", ["motya", "tg7615838255", "u-c1", "a_b-c",
                                  "x" * 32, "1abc", "abc9"])
def test_login_accept(helper, good):
    assert helper.LOGIN_RE.fullmatch(good), f"login regex rejected {good!r}"


def test_login_cannot_start_with_dash(helper):
    """Leading dash would be parsed as a flag by anything taking login on argv."""
    for bad in ("-rf", "--recursive-force", "-u", "-"):
        assert not helper.LOGIN_RE.fullmatch(bad)


def test_bot_created_account_is_never_admin():
    """Rights are derived from ADMIN_ONLY — the request body cannot widen them."""
    rights = {r: (r not in ADMIN_ONLY) for r in RIGHTS}
    assert not rights["users_manage"]
    assert not rights["commands_edit"]
    assert rights["files"] and rights["terminal"] and rights["overview"]


def test_create_rejects_bad_login(helper):
    helper.create({"login": "../etc", "password": "x" * 12, "slot": "motya"})
    assert "bad login" in result(helper)["msg"]


def test_create_rejects_short_password(helper):
    helper.create({"login": "probe", "password": "short", "slot": "motya"})
    assert "password min 8" in result(helper)["msg"]


def test_create_rejects_reserved_slot(helper, env):
    """No pre-declared list anymore, but reserved names stay off-limits."""
    helper.create({"login": "probe", "password": "x" * 12, "slot": "root"})
    assert "slot:" in result(helper)["msg"]
    assert not result(helper)["ok"]


def test_create_rejects_bad_slot_name(helper, env):
    helper.create({"login": "probe", "password": "x" * 12, "slot": "../etc"})
    assert "slot:" in result(helper)["msg"]


def test_done_result_is_owner_readable_only(helper):
    """res.json carries the created login: never world- or group-readable."""
    helper.done(True, "ok", login="motya", slot="motya")
    mode = helper.RES.stat().st_mode & 0o777
    assert mode & 0o077 == 0, f"res.json too open: {oct(mode)}"


def test_req_file_is_consumed(helper, env, monkeypatch):
    """The request carries a plaintext password; it must not survive the run."""
    helper.REQ.write_text(json.dumps({"op": "create", "login": "bad login",
                                      "password": "x" * 12, "slot": "motya"}))
    helper.main()
    assert not helper.REQ.exists()
    assert result(helper)["ok"] is False


class _Row(dict):
    def __getitem__(self, k):
        return dict.get(self, k)


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _FakeCon:
    def __init__(self, rows):
        self._rows = rows
        self.executed = []

    def execute(self, q, args=()):
        self.executed.append(q)
        return _FakeResult(self._rows)

    def commit(self):
        pass

    def close(self):
        pass


def test_revoke_refuses_admin_accounts(helper, monkeypatch):
    """A bot command must never delete the human admin."""
    con = _FakeCon([_Row(id=1, slot="motya", is_admin=1)])
    monkeypatch.setattr(helper.D, "connect", lambda *a, **k: con)
    helper.revoke({"login": "rxzwu"})
    assert not result(helper)["ok"]
    assert "admin" in result(helper)["msg"]
    assert not any("DELETE FROM users" in q for q in con.executed)


def test_revoke_unknown_user_is_not_an_error_crash(helper, monkeypatch):
    con = _FakeCon([])
    monkeypatch.setattr(helper.D, "connect", lambda *a, **k: con)
    helper.revoke({"login": "ghost"})
    assert not result(helper)["ok"]
    assert "no dashboard user" in result(helper)["msg"]


# ---------- wipe_slot: cleanup for slots a revoke left behind ----------

def test_wipe_slot_unknown_refused(helper, monkeypatch):
    monkeypatch.setattr(helper.PR, "registered_slots", lambda db: ["motya"])
    helper.wipe_slot({"slot": "itsmax"})
    assert not result(helper)["ok"]
    assert "no such slot" in result(helper)["msg"]


def test_wipe_slot_refuses_one_still_assigned(helper, monkeypatch):
    """The account must go first — otherwise the user loses its home."""
    monkeypatch.setattr(helper.PR, "registered_slots", lambda db: ["motya"])
    monkeypatch.setattr(helper.D, "connect",
                        lambda *a, **k: _FakeCon([_Row(id=7)]))
    helper.wipe_slot({"slot": "motya"})
    assert not result(helper)["ok"]
    assert "still assigned" in result(helper)["msg"]


def test_wipe_slot_delegates_to_provision(helper, monkeypatch):
    monkeypatch.setattr(helper.PR, "registered_slots", lambda db: ["motya"])
    monkeypatch.setattr(helper.D, "connect", lambda *a, **k: _FakeCon([]))
    seen = {}

    def fake_remove(db, slot, wipe=False):
        seen.update(slot=slot, wipe=wipe)
        return {"ok": True, "msg": "wiped", "log": ["wiped"]}

    monkeypatch.setattr(helper.PR, "remove_slot", fake_remove)
    helper.wipe_slot({"slot": "motya"})
    assert result(helper)["ok"] is True
    assert seen == {"slot": "motya", "wipe": True}


def test_main_dispatches_wipe_slot(helper, monkeypatch):
    monkeypatch.setattr(helper, "wipe_slot",
                        lambda req: helper.done(True, f"op={req['op']}"))
    helper.REQ.write_text(json.dumps({"op": "wipe_slot", "slot": "motya"}))
    helper.main()
    assert result(helper)["msg"] == "op=wipe_slot"
