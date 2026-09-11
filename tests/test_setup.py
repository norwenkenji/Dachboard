"""Setup bootstrap + pre-registered password flow."""
from conftest import login


def test_setup_flow(clients, env, tmp_path):
    import app.main as main
    from app import db as D
    from contextlib import closing
    # wipe admins to trigger setup mode
    with closing(D.connect(main.DB)) as con:
        con.execute("DELETE FROM users WHERE is_admin=1")
        con.commit()
    c = clients["admin"]
    assert c.get("/api/setup-needed").json() == {"needed": True}
    assert c.post("/api/setup", json={"token": "wrong", "login": "root",
                                      "password": "longpassword1"}).status_code == 403
    tok = main.ensure_setup_token()
    assert tok
    r = c.post("/api/setup", json={"token": tok, "login": "root",
                                   "password": "longpassword1"})
    assert r.status_code == 200, r.text
    assert c.get("/api/setup-needed").json() == {"needed": False}
    # token burned, second use 404
    r = c.post("/api/setup", json={"token": tok, "login": "root2",
                                   "password": "longpassword1"})
    assert r.status_code == 404
    # new admin can log in
    r = c.post("/api/login", json={"login": "root", "password": "longpassword1"})
    assert r.status_code == 200


def test_must_change_flow(clients):
    csrf = login(clients["admin"], "admin")
    a = clients["admin"]
    r = a.post("/api/users", json={"login": "pre", "password": "temp-pass-1",
                                   "rights": {"overview": True}, "limits": {}},
               headers={"X-CSRF-Token": csrf})
    uid = r.json()["id"]
    r = a.put(f"/api/users/{uid}", json={"must_change_pw": True},
              headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    b = clients["bob"]
    r = b.post("/api/login", json={"login": "pre", "password": "temp-pass-1"})
    assert r.status_code == 401
    assert r.json()["detail"] == {"must_change": True}
    # wrong old password rejected
    r = b.post("/api/first-password", json={"login": "pre", "old_password": "nope",
                                            "new_password": "my-own-pass-1"})
    assert r.status_code == 401
    # set own password, then login works
    r = b.post("/api/first-password", json={"login": "pre", "old_password": "temp-pass-1",
                                            "new_password": "my-own-pass-1"})
    assert r.status_code == 200
    r = b.post("/api/login", json={"login": "pre", "password": "my-own-pass-1"})
    assert r.status_code == 200
    # temp password dead
    r = b.post("/api/login", json={"login": "pre", "password": "temp-pass-1"})
    assert r.status_code == 401


def test_me_password_change(clients):
    csrf = login(clients["bob"], "bob")
    b = clients["bob"]
    r = b.post("/api/me/password", json={"old_password": "wrong",
                                         "new_password": "brand-new-1"},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code == 401
    r = b.post("/api/me/password", json={"old_password": "pass-bob",
                                         "new_password": "brand-new-1"},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    r = b.post("/api/login", json={"login": "bob", "password": "brand-new-1"})
    assert r.status_code == 200
