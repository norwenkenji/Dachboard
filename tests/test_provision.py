"""Dynamic slot provisioning: app/provision.py is the single code path shared
by the web UI (POST /api/slots, /api/users with a slot) and the Telegram bot's
root helper. These pin the guards and the registry math."""
import json
from contextlib import closing

import pytest

from app import db as D
from app import provision as PR


# ---------- name rules ----------

@pytest.mark.parametrize("bad", [
    "", "a", "x" * 31, "1abc", "-rf", "--help", "Zxc", "motya slot",
    "motya;rm", "motya`id`", "motya$(id)", "motya|id", "u-c4\nid",
    "a.b", "a@b", "a/b", "a\\b", "мотя", "zxc", "root", "admin",
    "dachboard", "dach-ttyd", "systemd-x", "nginx1", "ttyd-a",
])
def test_name_error_rejects(bad):
    assert PR.name_error(bad, set()) is not None, f"accepted {bad!r}"


@pytest.mark.parametrize("good", [
    "ab", "motya", "tg7615838255", "u-c1", "a_b-c", "z" * 30, "m9",
])
def test_name_error_accepts(good):
    assert PR.name_error(good, set()) is None, f"rejected {good!r}"


def test_name_error_refuses_existing_linux_user(monkeypatch):
    """The whole point: provisioning an existing account's name would hand out
    a shell as that account. Only slots we own are reusable."""
    monkeypatch.setattr(PR.R, "user_exists", lambda n: n in ("zxc", "motya"))
    assert PR.name_error("motya", set()) is not None          # not ours -> refuse
    assert PR.name_error("motya", {"motya"}) is None          # ours -> reuse ok


def test_reserved_names_refused_even_if_no_such_user(monkeypatch):
    monkeypatch.setattr(PR.R, "user_exists", lambda n: False)
    for name in ("root", "zxc", "dachboard", "admin", "nginx"):
        assert PR.name_error(name, set()) is not None


# ---------- templates ----------

def test_ttyd_unit_renders():
    body = PR.ttyd_unit("motya", 7685)
    assert "User=motya" in body
    assert "-p 7685" in body
    assert "dach-motya" in body          # tmux socket is per-slot
    assert "{" not in body and "}" not in body


def test_nginx_conf_renders_with_static_slot_header():
    body = PR.nginx_term_conf("motya", 7685)
    assert "location /term/motya/ {" in body
    assert "proxy_pass http://127.0.0.1:7685/;" in body
    assert "X-Slot motya;" in body
    assert "auth_request /dash-auth-motya;" in body
    # no leftover python format placeholders (nginx braces are literal here)
    assert "{slot}" not in body and "{port}" not in body


# ---------- registry: slot -> stable port ----------

def test_registry_roundtrip(env):
    db = env["db"]
    assert PR.registered_slots(db) == []
    PR.register_slot(db, "motya", 7685)
    PR.register_slot(db, "zxcpsycho", 7686)
    assert PR.registered_slots(db) == ["motya", "zxcpsycho"]
    assert PR.port_of(db, "motya") == 7685
    assert PR.port_of(db, "nope") is None


def test_allocate_port_lowest_free(env):
    db = env["db"]
    assert PR.allocate_port(db, base=7681) == 7681
    PR.register_slot(db, "a1", 7681)
    assert PR.allocate_port(db, base=7681) == 7682
    PR.register_slot(db, "a2", 7682)
    assert PR.allocate_port(db, base=7681) == 7683


def test_allocate_port_skips_root_port(env):
    """base-1 is the root shell: never hand it to a slot."""
    db = env["db"]
    PR.register_slot(db, "a1", 7681)
    assert PR.allocate_port(db, base=7681) != 7680


def test_port_exhaustion_raises(env):
    db = env["db"]
    with closing(D.connect(db)) as con:
        for p in range(7681, 7800):
            con.execute("INSERT INTO slots(slot,port,created_at) VALUES(?,?,1)",
                        (f"s{p}", p))
        con.commit()
    with pytest.raises(ValueError):
        PR.allocate_port(db, base=7681, top=7799)


def test_slot_port_reads_registry(env, monkeypatch):
    """The app resolves a dynamic slot's port from the registry, not from
    config.yaml order."""
    from app import deps as P
    monkeypatch.setattr(P, "DB", env["db"])
    PR.register_slot(env["db"], "motya", 7690)
    assert P.slot_port("motya") == 7690
    assert P.slot_port("root") == 7680


def test_legacy_config_slot_still_resolves(env, monkeypatch):
    from app import deps as P
    monkeypatch.setattr(P, "DB", env["db"])
    monkeypatch.setitem(P.CFG, "slots", ["u-c1", "u-c2"])
    assert P.slot_port("u-c2") == 7682
    assert P.slot_port("unknown") is None
