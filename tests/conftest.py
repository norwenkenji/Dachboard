import json
import sys
import time
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import auth as A
from app import db as D
from app import deps as P


@pytest.fixture()
def env(tmp_path, monkeypatch):
    db = str(tmp_path / "dach.sqlite3")
    monkeypatch.setattr(main, "DB", db)
    monkeypatch.setattr(P, "DB", db)
    monkeypatch.setitem(main.CFG, "cookie_secure", False)
    monkeypatch.setitem(main.CFG, "session_ttl_hours", 1)
    monkeypatch.setitem(main.CFG, "tunnel", {
        "provider": sys.executable, "args": ["-c", "print('see https://t.example.com')"],
        "cache_seconds": 0, "cache_file": str(tmp_path / "tunnel.txt"),
    })
    main.LOGIN_FAILS.clear()
    D.init(db)
    homes = {}
    for login, admin, rights, slot in [
        ("admin", 1, {}, "u-admin"),
        ("bob", 0, {"overview": True, "commands_run": True, "files": True,
                     "tunnel_view": True}, "u-bob"),
    ]:
        home = tmp_path / ("home-" + login)
        home.mkdir()
        homes[login] = str(home)
        with closing(D.connect(db)) as con:
            con.execute(
                "INSERT INTO users(login,pass_hash,is_admin,rights,limits,slot,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (login, A.hash_password("pass-" + login), admin,
                 json.dumps(rights), "{}", slot, int(time.time())))
            con.commit()

    def fake_home(user, slot=None):
        if user["is_admin"] and slot:
            for login, home in homes.items():
                if slot in (login, "u-" + login, user["slot"]):
                    return __import__("pathlib").Path(home)
            raise ValueError("unknown slot in test")
        for login, home in homes.items():
            if user["login"] == login:
                return __import__("pathlib").Path(home)
        raise ValueError("no home in test")

    monkeypatch.setattr(main, "home_of", fake_home)
    monkeypatch.setattr(P, "home_of", fake_home)
    return {"db": db, "homes": homes}


@pytest.fixture()
def clients(env):
    with TestClient(main.app) as admin_c, TestClient(main.app) as bob_c:
        yield {"admin": admin_c, "bob": bob_c}


def login(c, who, pw=None):
    r = c.post("/api/login", json={"login": who, "password": pw or f"pass-{who}"})
    assert r.status_code == 200, r.text
    return r.json()["csrf"]
