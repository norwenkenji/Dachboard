import json
import zipfile
from contextlib import closing

import pytest
from conftest import login

import app.main as main
from app import auth as A
from app import db as D
from app import deps as P


def mint(env, rights: dict, slot: str | None = "u-bob") -> str:
    """Create a machine token, return the raw bearer string."""
    tok, digest = A.api_token()
    with closing(D.connect(P.DB)) as con:
        con.execute(
            "INSERT INTO api_tokens(name,token_hash,rights,slot,created_at)"
            " VALUES(?,?,?,?,?)",
            ("tok-" + tok[-6:], digest, json.dumps(rights), slot, 0))
        con.commit()
    return tok


def bearer(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


def test_bearer_metrics_and_files(env, clients):
    tok = mint(env, {"overview": True, "files": True})
    c = clients["bob"]
    r = c.get("/api/metrics", headers=bearer(tok))
    assert r.status_code == 200, r.text
    r = c.get("/api/files", headers=bearer(tok))
    assert r.status_code == 200, r.text
    entries = r.json()["entries"]
    assert isinstance(entries, list)


def test_bearer_denied_without_right(env, clients):
    tok = mint(env, {"overview": True})
    c = clients["bob"]
    r = c.get("/api/files", headers=bearer(tok))
    assert r.status_code == 403


def test_bearer_cannot_mint_tokens(env, clients):
    tok = mint(env, {"overview": True, "files": True})
    c = clients["bob"]
    r = c.post("/api/tokens", headers=bearer(tok), json={"name": "evil"})
    assert r.status_code == 403


def test_bearer_files_scoped_to_slot_home(env, clients):
    tok = mint(env, {"files": True}, slot="u-bob")
    c = clients["bob"]
    r = c.post("/api/files/write", headers=bearer(tok),
               json={"path": "from-mcp.txt", "content": "hi"})
    assert r.status_code == 200, r.text
    home = env["homes"]["bob"]
    assert (home_cmp := __import__("pathlib").Path(home) / "from-mcp.txt").read_text() == "hi"
    r = c.post("/api/files/write", headers=bearer(tok),
               json={"path": "../admin-secret", "content": "x"})
    assert r.status_code == 400  # escape blocked


def test_bearer_commands_edit(env, clients):
    tok = mint(env, {"commands_run": True, "commands_edit": True})
    c = clients["bob"]
    r = c.post("/api/commands", headers=bearer(tok),
               json={"name": "mcp-echo", "argv": ["/bin/echo", "mcp"]})
    assert r.status_code == 200, r.text
    cid = r.json()["id"]
    r = c.post(f"/api/commands/{cid}/run", headers=bearer(tok))
    assert r.status_code in (200, 403)  # 403 on Windows (no runuser); 200 on linux


def test_bearer_bad_token(env, clients):
    c = clients["bob"]
    r = c.get("/api/metrics", headers=bearer("dach_invalid"))
    assert r.status_code == 401


def test_unzip_zip_slip_blocked(env, clients):
    from app import files as F
    import pathlib
    home = pathlib.Path(env["homes"]["bob"])
    zpath = home / "evil.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("../../escape.txt", "pwn")
    tok = mint(env, {"files": True}, slot="u-bob")
    c = clients["bob"]
    r = c.post("/api/files/unzip", headers=bearer(tok),
               json={"path": "evil.zip"})
    assert r.status_code == 400
    assert "escape" in r.text or "escaping" in r.text
    assert not (home.parent / "escape.txt").exists()


def test_unzip_ok(env, clients):
    import pathlib
    home = pathlib.Path(env["homes"]["bob"])
    zpath = home / "site.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("app/main.py", "print(1)")
        z.writestr("README.md", "# hi")
    tok = mint(env, {"files": True}, slot="u-bob")
    c = clients["bob"]
    r = c.post("/api/files/unzip", headers=bearer(tok),
               json={"path": "site.zip", "into": "deploy"})
    assert r.status_code == 200, r.text
    assert (home / "deploy" / "app" / "main.py").read_text() == "print(1)"
    assert (home / "deploy" / "README.md").read_text() == "# hi"


def test_unzip_symlink_member_blocked(env, clients):
    import io
    import pathlib
    import zipfile as zf
    home = pathlib.Path(env["homes"]["bob"])
    zpath = home / "link.zip"
    zi = zf.ZipInfo("evil-link")
    zi.external_attr = (0o120000 << 16)
    with zf.ZipFile(zpath, "w") as z:
        z.writestr(zi, "/etc/passwd")
    tok = mint(env, {"files": True}, slot="u-bob")
    c = clients["bob"]
    r = c.post("/api/files/unzip", headers=bearer(tok), json={"path": "link.zip"})
    assert r.status_code == 400
    assert "symlink" in r.text


def test_upload_multi_and_sanitize(env, clients):
    tok = mint(env, {"files": True}, slot="u-bob")
    c = clients["bob"]
    r = c.post("/api/files/upload", headers=bearer(tok),
               files=[("file", ("a.txt", b"aaa", "text/plain")),
                      ("file", ("../b.txt", b"bbb", "text/plain"))])
    assert r.status_code == 200, r.text
    names = [f["name"] for f in r.json()["files"]]
    assert names == ["a.txt", "_b.txt"]
    import pathlib
    home = pathlib.Path(env["homes"]["bob"])
    assert (home / "a.txt").exists()
    assert not (home.parent / "b.txt").exists()


def test_whoami_via_bearer(env, clients):
    tok = mint(env, {"overview": True})
    c = clients["bob"]
    r = c.get("/api/me", headers=bearer(tok))
    assert r.status_code == 200
    assert r.json()["via"] == "token"


def test_home_of_rejects_bad_slot(env):
    import app.deps as dep
    with pytest.raises(Exception):
        dep.home_of({"is_admin": True, "slot": None}, "u-c1/../../etc")
    with pytest.raises(Exception):
        dep.home_of({"is_admin": True, "slot": None}, "../etc")
