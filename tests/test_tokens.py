"""API tokens: any bot/site/code asks for the fresh tunnel with Bearer auth."""


def _admin_token(c, csrf, name="bot1", rights=None):
    r = c.post("/api/tokens",
               json={"name": name, "rights": rights or {"tunnel_view": True}},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.text
    return r.json()


def test_token_tunnel_no_cookie(clients):
    from conftest import login
    csrf = login(clients["admin"], "admin")
    t = _admin_token(clients["admin"], csrf)
    assert t["token"].startswith("dach_")
    # brand-new client, no session cookie at all
    from fastapi.testclient import TestClient

    import app.main as main
    with TestClient(main.app) as anon:
        r = anon.get("/api/tunnel",
                     headers={"Authorization": f"Bearer {t['token']}"})
        assert r.status_code == 200, r.text
        assert r.json()["url"] == "https://t.example.com"
        # refresh via bearer, no CSRF needed
        r = anon.post("/api/tunnel/refresh",
                      headers={"Authorization": f"Bearer {t['token']}"})
        assert r.status_code == 200


def test_token_scoped_and_revoked(clients):
    from conftest import login
    csrf = login(clients["admin"], "admin")
    a = clients["admin"]
    t = _admin_token(a, csrf, name="narrow", rights={"overview": True})
    from fastapi.testclient import TestClient

    import app.main as main
    with TestClient(main.app) as anon:
        h = {"Authorization": f"Bearer {t['token']}"}
        assert anon.get("/api/tunnel", headers=h).status_code == 403
        assert anon.get("/api/tunnel", headers={"Authorization": "Bearer junk"}).status_code == 401
        assert anon.get("/api/tunnel").status_code == 401
    toks = a.get("/api/tokens").json()
    assert any(x["name"] == "narrow" for x in toks)
    tid = next(x["id"] for x in toks if x["name"] == "narrow")
    assert a.delete(f"/api/tokens/{tid}", headers={"X-CSRF-Token": csrf}).status_code == 200
    with TestClient(main.app) as anon2:
        r = anon2.get("/api/tunnel", headers={"Authorization": f"Bearer {t['token']}"})
        assert r.status_code == 401


def test_token_admin_only(clients):
    from conftest import login
    csrf = login(clients["bob"], "bob")
    r = clients["bob"].post("/api/tokens", json={"name": "x"},
                            headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403
