"""End-to-end smoke test against a REAL uvicorn process.

The pytest suite drives the app through TestClient, which never proves that
`python -m app.main serve` — the actual systemd ExecStart — boots, binds, and
answers over a real socket. This does, and walks the security chain end to end:

  setup token -> create admin -> login -> upload evil.html ->
  download it (must be inert) -> preview it (must be refused) ->
  non-admin hits /api/services (must be 403) -> audit lines on disk

Deliberately NOT named `test_*.py`: it spawns a server process and binds a
real port, which is not something the default `pytest -q` run should do. Run it
by hand before deploying, or after touching headers/auth/file delivery:

    python tests/smoke_server.py            # Linux/macOS
    .venv\\Scripts\\python.exe tests\\smoke_server.py   # Windows

Exits non-zero and lists every failed check; the temp dir (config, db, server
log, audit log) is kept and printed so a failure can be inspected.
"""
import http.cookiejar
import json
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FAILS = []


def check(label, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + (f"   {detail}" if detail else ""))
    if not cond:
        FAILS.append(label)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _hdrs(resp):
    """Header dict with lowercased keys.

    Starlette stores response header names lowercased, and `dict.get` is
    case-sensitive, so without this every lookup silently returns None and the
    smoke test reports the *harness* as broken. httpx (used by pytest) hides
    this because its headers are case-insensitive.
    """
    return {k.lower(): v for k, v in resp.headers.items()}


def multipart(fields, fname, fbytes):
    boundary = "----smokeboundary1234"
    out = []
    for k, v in fields.items():
        out.append(f"--{boundary}\r\nContent-Disposition: form-data; "
                   f'name="{k}"\r\n\r\n{v}\r\n'.encode())
    out.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
               f"filename=\"{fname}\"\r\nContent-Type: text/html\r\n\r\n".encode())
    out.append(fbytes)
    out.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


def main():
    tmp = Path(tempfile.mkdtemp(prefix="dach-smoke-"))
    port = free_port()
    cfg = tmp / "config.yaml"
    cfg.write_text(
        f"host: 127.0.0.1\nport: {port}\ncookie_secure: false\n"
        f"session_ttl_hours: 1\nlog_level: INFO\n"
        f"secret_file: {tmp / '.secret'!s}\n"
        f"db_path: {tmp / 'd.sqlite3'!s}\n"
        f"audit:\n  file: {tmp / 'audit.log'!s}\n  file_enabled: true\n",
        encoding="utf-8")
    logfile = tmp / "server.log"
    base = f"http://127.0.0.1:{port}"

    print(f"[smoke] boot: python -m app.main serve --config {cfg.name}  (port {port})")
    # stdout/stderr go to a FILE, not a pipe: the sandbox forbids named pipes,
    # so subprocess.PIPE would fail with EPERM here.
    # The handle must outlive this statement (it is the child's stdout for its
    # whole life) and is closed deterministically in the finally below, which
    # is the one case SIM115 cannot see.
    fh = open(logfile, "wb")  # noqa: SIM115
    proc = subprocess.Popen([sys.executable, "-m", "app.main", "serve",
                             "--config", str(cfg)],
                            cwd=str(REPO), stdout=fh, stderr=subprocess.STDOUT)

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar))

    def req(method, path, data=None, headers=None, raw=False):
        r = urllib.request.Request(base + path, data=data, method=method,
                                   headers=headers or {})
        try:
            with opener.open(r, timeout=20) as resp:
                body = resp.read()
                return resp.status, _hdrs(resp), (body if raw else
                                                  body.decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            body = e.read()
            return e.code, _hdrs(e), (body if raw else
                                      body.decode("utf-8", "replace"))

    try:
        # ---- wait for the socket ----
        up = False
        for _ in range(120):
            if proc.poll() is not None:
                print("[smoke] server exited early:\n" +
                      logfile.read_text(encoding="utf-8", errors="replace")[-2000:])
                return 1
            try:
                socket.create_connection(("127.0.0.1", port), 0.5).close()
                up = True
                break
            except OSError:
                time.sleep(0.25)
        if not up:
            print("[smoke] server never bound the port")
            return 1
        print(f"[smoke] server up (pid {proc.pid})\n")

        # ---- 1. the SPA shell ----
        print("[1] GET / — shell, asset versions, hardening headers")
        st, hd, body = req("GET", "/")
        check("status 200", st == 200, str(st))
        check("shell has no hand-maintained ?v=23", "?v=23" not in body)
        m = re.search(r'static/js/00-core\.js\?v=([0-9a-f]{12})', body)
        check("asset URLs carry a 12-hex content hash", bool(m),
              m.group(1) if m else "not found")
        check("Content-Security-Policy present", "content-security-policy" in hd)
        check("X-Content-Type-Options: nosniff",
              hd.get("x-content-type-options") == "nosniff")
        check("X-Frame-Options: DENY", hd.get("x-frame-options") == "DENY")
        check("shell is no-store", hd.get("cache-control") == "no-store",
              str(hd.get("cache-control")))

        # ---- 2. the hashed asset really resolves ----
        print("\n[2] GET the hashed asset URL")
        if m:
            st2, hd2, _ = req("GET", f"/static/js/00-core.js?v={m.group(1)}")
            check("hashed asset 200", st2 == 200, str(st2))
            check("asset may be cached", "public" in (hd2.get("cache-control") or ""),
                  str(hd2.get("cache-control")))

        # ---- 3. bootstrap: setup token from the log ----
        print("\n[3] setup token -> create admin")
        logtxt = logfile.read_text(encoding="utf-8", errors="replace")
        setup_tok = None
        for line in logtxt.splitlines():
            if "SETUP" in line.upper():
                setup_tok = line.strip().split()[-1]
                break
        check("setup token logged", bool(setup_tok), setup_tok or "not found")
        if setup_tok:
            st3, _, b3 = req("POST", "/api/setup",
                             data=json.dumps({"token": setup_tok, "login": "admin",
                                              "password": "smokepass123"}).encode(),
                             headers={"Content-Type": "application/json"})
            check("admin created", st3 == 200, f"{st3} {b3[:120]}")
            st3b, _, _ = req("POST", "/api/setup",
                             data=json.dumps({"token": setup_tok, "login": "x",
                                              "password": "smokepass123"}).encode(),
                             headers={"Content-Type": "application/json"})
            check("setup token burned (second use refused)", st3b in (400, 403, 404),
                  str(st3b))

        # ---- 4. login ----
        print("\n[4] login")
        st4, _, b4 = req("POST", "/api/login",
                         data=json.dumps({"login": "admin",
                                          "password": "smokepass123"}).encode(),
                         headers={"Content-Type": "application/json"})
        check("login 200", st4 == 200, f"{st4} {b4[:120]}")
        csrf = json.loads(b4).get("csrf") if st4 == 200 else None
        check("csrf token returned", bool(csrf))

        # ---- 5. the stored-XSS chain ----
        print("\n[5] upload evil.html, then try to make it execute")
        evil = b"<html><body><script>fetch('/api/csrf').then(r=>r.text())" \
               b"</script>pwn</body></html>"
        payload, ctype = multipart({}, "evil.html", evil)
        st5, _, b5 = req("POST", "/api/files/upload", data=payload,
                         headers={"Content-Type": ctype, "X-CSRF-Token": csrf or ""})
        check("upload 200", st5 == 200, f"{st5} {b5[:120]}")

        st6, hd6, b6 = req("GET", "/api/files/download?path=evil.html", raw=True)
        check("download 200", st6 == 200, str(st6))
        check("Content-Type forced to octet-stream",
              hd6.get("content-type") == "application/octet-stream",
              str(hd6.get("content-type")))
        cd = hd6.get("content-disposition") or ""
        check("Content-Disposition: attachment", cd.startswith("attachment"), cd)
        check("filename preserved", 'evil.html' in cd, cd)
        check("download CSP cannot run anything",
              "default-src 'none'" in (hd6.get("content-security-policy") or "")
              and "sandbox" in (hd6.get("content-security-policy") or ""),
              str(hd6.get("content-security-policy")))
        check("bytes intact (so it still downloads usefully)", b6 == evil)

        st7, _hd7, _b7 = req("GET", "/api/files/preview?path=evil.html")
        check("preview of active content refused with 415", st7 == 415, str(st7))

        st8, _b8h, _b8 = req("GET", "/api/files/download?path=../.secret", raw=True)
        check("path escape refused", st8 in (400, 403, 404), str(st8))

        # ---- 6. RBAC: non-admin must not reach systemctl ----
        print("\n[6] non-admin token/session vs /api/services")
        dbp = tmp / "d.sqlite3"
        con = sqlite3.connect(str(dbp))
        con.execute("PRAGMA busy_timeout=5000")
        # reuse the app's own scrypt hash so the password actually works
        sys.path.insert(0, str(REPO))
        from app import auth as A
        from app.rbac import RIGHTS
        rights = {r: (r in ("overview", "files", "containers_view",
                            "containers_control")) for r in RIGHTS}
        con.execute("INSERT INTO users(login,pass_hash,is_admin,rights,limits,slot,"
                    "must_change_pw,created_at) VALUES(?,?,0,?,?,?,0,?)",
                    ("smokebob", A.hash_password("bobpass123"),
                     json.dumps(rights), "{}", "smokebob", int(time.time())))
        con.commit()
        con.close()

        jar2 = http.cookiejar.CookieJar()
        op2 = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar2))

        def req2(method, path, data=None, headers=None):
            r = urllib.request.Request(base + path, data=data, method=method,
                                       headers=headers or {})
            try:
                with op2.open(r, timeout=20) as resp:
                    return resp.status, resp.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                return e.code, e.read().decode("utf-8", "replace")

        stb, bb = req2("POST", "/api/login",
                       data=json.dumps({"login": "smokebob",
                                        "password": "bobpass123"}).encode(),
                       headers={"Content-Type": "application/json"})
        check("non-admin login 200", stb == 200, f"{stb} {bb[:120]}")
        csrfb = json.loads(bb).get("csrf") if stb == 200 else ""

        stc, _ = req2("GET", "/api/services")
        check("non-admin GET /api/services -> 403 (systemctl is admin-only)",
              stc == 403, str(stc))
        std, _ = req2("POST", "/api/services/sshd.service/stop",
                      headers={"Content-Type": "application/json",
                               "X-CSRF-Token": csrfb}, data=b"{}")
        check("non-admin stop sshd.service -> 403", std == 403, str(std))
        ste, _ = req2("GET", "/api/services/dachboard.service/logs")
        check("non-admin journal read -> 403", ste == 403, str(ste))
        stf, _ = req2("GET", "/api/containers")
        check("non-admin GET /api/containers still allowed (delegable right)",
              stf in (200, 500), str(stf))

        # ---- 7. audit trail actually written ----
        print("\n[7] audit trail")
        alog = tmp / "audit.log"
        atxt = alog.read_text(encoding="utf-8", errors="replace") if alog.exists() else ""
        check("audit file written", bool(atxt), str(alog))
        for ev in ("event=boot", "event=setup", "event=login", "event=denied"):
            check(f"audit contains {ev}", ev in atxt)
        check("no password leaked into the audit trail",
              "smokepass123" not in atxt and "bobpass123" not in atxt)
        check("actor recorded for the denial",
              "actor=smokebob" in atxt or "actor=admin" in atxt)
        dm = re.search(r"event=denied right=(\S+)", atxt)
        check("denied right is services_view/control",
              bool(dm) and dm.group(1) in ("services_view", "services_control"),
              dm.group(1) if dm else "none")

        # ---- 8. rate limit ----
        print("\n[8] login throttle")
        codes = [req2("POST", "/api/login",
                      data=json.dumps({"login": "smokebob",
                                       "password": "wrongpass"}).encode(),
                      headers={"Content-Type": "application/json"})[0]
                 for _ in range(12)]
        check("429 appears after repeated failures", 429 in codes, str(codes))
        stg, _ = req2("POST", "/api/login",
                      data=json.dumps({"login": "smokebob",
                                       "password": "bobpass123"}).encode(),
                      headers={"Content-Type": "application/json"})
        check("correct password also blocked while throttled", stg == 429, str(stg))

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        fh.close()

    print("\n" + "=" * 62)
    if FAILS:
        print(f"SMOKE FAIL: {len(FAILS)} check(s)")
        for f in FAILS:
            print("   -", f)
        print(f"\nserver log: {logfile}")
        return 1
    print("SMOKE PASS — real uvicorn boot + full security chain verified")
    print(f"(temp dir kept for inspection: {tmp})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
