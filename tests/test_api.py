"""Full-stack API tests: auth, CSRF, RBAC gates, CRUD, runs, files, tunnel."""
import sys

from conftest import login


def test_login_bad_password(clients):
    r = clients["bob"].post("/api/login", json={"login": "bob", "password": "nope"})
    assert r.status_code == 401


def test_me_and_logout(clients):
    login(clients["bob"], "bob")
    assert clients["bob"].get("/api/me").json()["login"] == "bob"
    csrf = login(clients["admin"], "admin")
    clients["admin"].post("/api/logout", headers={"X-CSRF-Token": csrf})
    assert clients["admin"].get("/api/me").status_code == 401


def test_csrf_required(clients):
    login(clients["admin"], "admin")
    r = clients["admin"].post("/api/tunnel/refresh")
    assert r.status_code == 403


def test_bob_cannot_manage_users(clients):
    csrf = login(clients["bob"], "bob")
    r = clients["bob"].get("/api/users")
    assert r.status_code == 403
    r = clients["bob"].post("/api/users", json={}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403


def test_admin_users_crud(clients):
    csrf = login(clients["admin"], "admin")
    c = clients["admin"]
    assert len(c.get("/api/users").json()) == 2
    r = c.post("/api/users", json={"login": "eve", "password": "password-1",
                                   "rights": {"overview": True}, "limits": {}},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    eid = r.json()["id"]
    r = c.put(f"/api/users/{eid}",
              json={"rights": {"overview": True, "files": True}, "limits": {"disk_quota": "1G"}},
              headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    users = {u["login"]: u for u in c.get("/api/users").json()}
    assert users["eve"]["rights"]["files"] is True
    assert users["eve"]["limits"]["disk_quota"] == "1G"
    # self-delete forbidden
    me = c.get("/api/me").json()
    r = c.delete(f"/api/users/{me['id']}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 400
    r = c.delete(f"/api/users/{eid}", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200


def test_rename_login(clients):
    csrf = login(clients["admin"], "admin")
    a = clients["admin"]
    me = a.get("/api/me").json()
    r = a.put(f"/api/users/{me['id']}", json={"login": "rxzwu"},
              headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    assert a.get("/api/me").json()["login"] == "rxzwu"
    r = a.put(f"/api/users/{me['id']}", json={"login": "bob"},
              headers={"X-CSRF-Token": csrf})
    assert r.status_code == 400
    r = a.put(f"/api/users/{me['id']}", json={"login": "admin"},
              headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200


def test_users_validation(clients):
    csrf = login(clients["admin"], "admin")
    c = clients["admin"]
    r = c.post("/api/users", json={"login": "", "password": "password-1"},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code == 400
    r = c.post("/api/users", json={"login": "short", "password": "123"},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code == 400


def test_commands_flow(clients):
    acsrf = login(clients["admin"], "admin")
    bcsrf = login(clients["bob"], "bob")
    a, b = clients["admin"], clients["bob"]
    argv = [sys.executable, "-c", "print('ran-ok')"]
    r = a.post("/api/commands",
               json={"name": "probe", "argv": argv, "run_as": "self",
                     "allowed": [], "timeout_sec": 20},
               headers={"X-CSRF-Token": acsrf})
    cid = r.json()["id"]
    # bob not in allow-list
    r = b.post(f"/api/commands/{cid}/run", headers={"X-CSRF-Token": bcsrf})
    assert r.status_code == 403
    # admin allows bob
    r = a.put(f"/api/commands/{cid}",
              json={"name": "probe", "argv": argv, "run_as": "self",
                    "allowed": [2], "timeout_sec": 20},
              headers={"X-CSRF-Token": acsrf})
    assert r.status_code == 200
    r = b.post(f"/api/commands/{cid}/run", headers={"X-CSRF-Token": bcsrf})
    assert r.status_code == 200
    assert r.json()["code"] == 0 and "ran-ok" in r.json()["output"]
    runs = b.get("/api/runs").json()
    assert runs and runs[0]["exit_code"] == 0
    # constructor validation: shell strings rejected
    r = a.post("/api/commands",
               json={"name": "bad", "argv": "rm -rf /", "run_as": "self"},
               headers={"X-CSRF-Token": acsrf})
    assert r.status_code == 400
    r = a.delete(f"/api/commands/{cid}", headers={"X-CSRF-Token": acsrf})
    assert r.status_code == 200


def test_files_flow(clients, env):
    csrf = login(clients["bob"], "bob")
    b = clients["bob"]
    r = b.post("/api/files/write",
               json={"path": "note.txt", "content": "kent-was-here"},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    rows = b.get("/api/files").json()
    assert [x["name"] for x in rows] == ["note.txt"]
    r = b.get("/api/files/read", params={"path": "note.txt"})
    assert r.json()["content"] == "kent-was-here"
    # escape blocked at API level
    r = b.get("/api/files/read", params={"path": "../x"})
    assert r.status_code == 400
    r = b.post("/api/files/delete", json={"path": "note.txt"},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    q = b.get("/api/quota").json()
    assert q["used"] >= 0


def test_admin_files_other_slot(clients):
    login(clients["admin"], "admin")
    a = clients["admin"]
    r = a.get("/api/files", params={"slot": "u-bob"})
    assert r.status_code == 200


def test_metrics_services_containers(clients):
    login(clients["bob"], "bob")
    b = clients["bob"]
    m = b.get("/api/metrics").json()
    assert set(m) >= {"cpu", "mem", "disk", "temps", "load", "uptime"}
    assert isinstance(b.get("/api/metrics/history").json(), list)
    assert isinstance(b.get("/api/services").json(), list)


def test_tunnel(clients):
    login(clients["bob"], "bob")
    b = clients["bob"]
    assert b.get("/api/tunnel").json()["url"] == "https://t.example.com"


def test_terminal_gating(clients):
    bcsrf = login(clients["bob"], "bob")
    # fresh user without terminal right
    r = clients["bob"].post("/api/terminal/ensure",
                            json={}, headers={"X-CSRF-Token": bcsrf})
    assert r.status_code == 403
    acsrf = login(clients["admin"], "admin")
    r = clients["admin"].post("/api/terminal/ensure", json={"slot": "u-bob"},
                              headers={"X-CSRF-Token": acsrf})
    # passes RBAC; on machines without systemd it 500s — must never be 401/403
    assert r.status_code not in (401, 403)


def test_csrf_restore(clients):
    login(clients["bob"], "bob")
    r = clients["bob"].get("/api/csrf")
    assert r.status_code == 200 and len(r.json()["csrf"]) > 10
    assert clients["admin"].get("/api/csrf").status_code == 401


def test_service_logs_and_action(clients):
    acsrf = login(clients["admin"], "admin")
    a = clients["admin"]
    r = a.get("/api/services/cron.service/logs")
    assert r.status_code == 200 and isinstance(r.json()["logs"], str)
    r = a.get("/api/services/evil;rm/logs")
    assert r.status_code == 400
    bcsrf = login(clients["bob"], "bob")
    b = clients["bob"]
    r = b.post("/api/services/cron.service/restart",
               headers={"X-CSRF-Token": bcsrf})
    assert r.status_code == 403
    r = a.post("/api/services/cron.service/frobnicate",
               headers={"X-CSRF-Token": acsrf})
    assert r.status_code == 400


def test_admin_root_files_and_terminal(clients):
    csrf = login(clients["admin"], "admin")
    a = clients["admin"]
    # admin without slot sees the whole filesystem
    r = a.get("/api/files")
    assert r.status_code == 200 and isinstance(r.json(), list)
    # non-admin may not take root shell
    bcsrf = login(clients["bob"], "bob")
    r = clients["bob"].post("/api/terminal/ensure", json={"slot": "root"},
                            headers={"X-CSRF-Token": bcsrf})
    assert r.status_code == 403
    # admin root request passes RBAC (500 here = no systemd, never 401/403)
    r = a.post("/api/terminal/ensure", json={"slot": "root"},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code not in (401, 403)


def test_containers_gating(clients):
    login(clients["bob"], "bob")
    assert clients["bob"].get("/api/containers").status_code == 403
    login(clients["admin"], "admin")
    assert clients["admin"].get("/api/containers").status_code == 200
