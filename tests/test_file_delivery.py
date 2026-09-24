"""File delivery: forced-download headers, preview allow-list, range requests.

These are the HTTP half of the stored-XSS fix. The path-resolution half lives
in test_safepath.py; this one pins what actually reaches the browser.
"""
import os
from pathlib import Path

import pytest
from conftest import login

from app import fileserv
from app.fileserv import _UNSAT, _parse_range

#: On Windows a descriptor opened without O_BINARY stops at the first 0x1A
#: (SUB, the historical EOF marker), so a payload of bytes(range(256)) would
#: silently read as 26 bytes. safepath always passes O_BINARY; these tests open
#: descriptors directly, so they have to as well.
_O_BINARY = getattr(os, "O_BINARY", 0)


def _open_ro(path) -> int:
    return os.open(str(path), os.O_RDONLY | _O_BINARY)


@pytest.fixture()
def home_with_files(clients, env):
    """bob's home with one file of every interesting shape."""
    home = Path(env["homes"]["bob"])
    (home / "doc.pdf").write_bytes(b"%PDF-1.4 not really\n")
    (home / "pic.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(64)))
    (home / "evil.html").write_text("<script>alert(1)</script>")
    (home / "evil.svg").write_text('<svg onload="alert(1)"></svg>')
    (home / "app.js").write_text("alert(1)")
    (home / "notes.txt").write_text("hello")
    (home / "blob.bin").write_bytes(bytes(range(256)))
    (home / "sub").mkdir()
    return home


# ---------- download: never a document on the panel origin ----------

def test_download_forces_attachment_and_opaque_type(clients, home_with_files):
    login(clients["bob"], "bob")
    b = clients["bob"]
    for name in ("evil.html", "evil.svg", "app.js", "pic.png", "doc.pdf"):
        r = b.get("/api/files/download", params={"path": name})
        assert r.status_code == 200, (name, r.text)
        assert r.headers["content-type"] == "application/octet-stream", name
        assert r.headers["content-disposition"].startswith("attachment"), name
        assert r.headers["x-content-type-options"] == "nosniff", name
        # the browser must have no way to reinterpret the bytes
        assert "text/html" not in r.headers["content-type"]
        assert "image/svg" not in r.headers["content-type"]


def test_download_body_is_the_real_file(clients, home_with_files):
    login(clients["bob"], "bob")
    r = clients["bob"].get("/api/files/download", params={"path": "blob.bin"})
    assert r.content == bytes(range(256))
    assert r.headers["content-length"] == "256"


@pytest.mark.parametrize("name,want", [
    ('quo"te.txt', 'attachment; filename="quo\\"te.txt"'),
    ("back\\slash.txt", 'attachment; filename="back_slash.txt"'),
    ("/etc/passwd", 'attachment; filename="_etc_passwd"'),
    ("..\r\nSet-Cookie: x", 'attachment; filename="..Set-Cookie: x"'),
    ("", 'attachment; filename="download"'),
    ("   ", 'attachment; filename="download"'),
])
def test_content_disposition_cannot_be_broken_out_of(name, want):
    """A quote, CRLF or slash in the name must not escape the header.

    The name is fully user-controlled, and a smuggled CRLF here is a response
    splitting primitive on the panel's own origin.
    """
    from app import security as SEC
    assert SEC.attachment_headers(name)["Content-Disposition"] == want
    cd = SEC.attachment_headers(name)["Content-Disposition"]
    assert "\r" not in cd and "\n" not in cd


def test_download_refuses_a_directory(clients, home_with_files):
    login(clients["bob"], "bob")
    assert clients["bob"].get(
        "/api/files/download", params={"path": "sub"}).status_code == 400


# ---------- preview: allow-list only ----------

def test_preview_refuses_active_types(clients, home_with_files):
    login(clients["bob"], "bob")
    b = clients["bob"]
    for name in ("evil.html", "evil.svg", "app.js"):
        r = b.get("/api/files/preview", params={"path": name})
        assert r.status_code == 415, (name, r.status_code)


def test_preview_serves_passive_media_inline(clients, home_with_files):
    login(clients["bob"], "bob")
    b = clients["bob"]
    r = b.get("/api/files/preview", params={"path": "pic.png"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/png"
    assert r.headers["content-disposition"].startswith("inline")
    assert r.headers["x-content-type-options"] == "nosniff"
    r = b.get("/api/files/preview", params={"path": "doc.pdf"})
    assert r.headers["content-type"] == "application/pdf"


def test_preview_csp_is_locked_down_but_iframeable(clients, home_with_files):
    """The SPA embeds previews in an <iframe>, so framing must stay same-origin.

    ``DENY`` would break the PDF viewer, and a sandboxed CSP would too (Chrome's
    plugin refuses a unique origin) — while buying nothing here, since only
    passive types ever reach this endpoint.
    """
    login(clients["bob"], "bob")
    b = clients["bob"]
    for name in ("pic.png", "doc.pdf", "notes.txt"):
        r = b.get("/api/files/preview", params={"path": name})
        assert r.status_code == 200, name
        csp = r.headers["content-security-policy"]
        assert "script-src" not in csp, (name, csp)
        assert "'unsafe-inline'" not in csp, (name, csp)
        assert "sandbox" not in csp, (name, csp)
        assert "frame-ancestors 'self'" in csp, (name, csp)
        assert r.headers["x-frame-options"] == "SAMEORIGIN", name


def test_preview_body_is_the_real_file(clients, home_with_files):
    login(clients["bob"], "bob")
    png = b"\x89PNG\r\n\x1a\n" + bytes(range(64))
    r = clients["bob"].get("/api/files/preview", params={"path": "pic.png"})
    assert r.content == png


def test_preview_unknown_extension_refused(clients, home_with_files):
    login(clients["bob"], "bob")
    assert clients["bob"].get(
        "/api/files/preview", params={"path": "blob.bin"}).status_code == 415


# ---------- global hardening middleware ----------

def test_every_response_carries_security_headers(clients):
    login(clients["bob"], "bob")
    for path in ("/api/me", "/api/files", "/static/js/00-core.js"):
        r = clients["bob"].get(path)
        assert r.status_code == 200, path
        assert r.headers["x-content-type-options"] == "nosniff", path
        assert "default-src" in r.headers["content-security-policy"], path
        assert r.headers["referrer-policy"] == "no-referrer", path


def test_panel_is_not_frameable_by_other_sites(clients):
    login(clients["bob"], "bob")
    r = clients["bob"].get("/api/me")
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_endpoint_csp_wins_over_the_middleware(clients, home_with_files):
    """A preview must keep its own CSP; the global one would forbid the media."""
    login(clients["bob"], "bob")
    r = clients["bob"].get("/api/files/preview", params={"path": "pic.png"})
    assert r.headers["content-security-policy"].count("default-src") == 1


def test_static_may_cache_but_nothing_else_may(clients):
    login(clients["bob"], "bob")
    b = clients["bob"]
    assert "max-age" in b.get("/static/js/00-core.js").headers["cache-control"]
    for path in ("/api/me", "/api/files"):
        assert b.get(path).headers["cache-control"] == "no-store", path


def test_unauthenticated_error_still_hardened(clients):
    r = clients["bob"].get("/api/me")
    assert r.status_code == 401
    assert r.headers["x-content-type-options"] == "nosniff"


# ---------- byte ranges (<video>/<audio> seeking) ----------

@pytest.mark.parametrize("hdr,expected", [
    ("bytes=0-9", (0, 10)),
    ("bytes=10-19", (10, 20)),
    ("bytes=250-", (250, 256)),
    ("bytes=-6", (250, 256)),
    ("bytes=0-1000", (0, 256)),          # clamped to the real size
])
def test_range_parsing(hdr, expected):
    assert _parse_range(hdr, 256) == expected


@pytest.mark.parametrize("hdr", [
    "bytes=256-", "bytes=300-400", "bytes=-0", "bytes=5-1",
])
def test_unsatisfiable_ranges(hdr):
    assert _parse_range(hdr, 256) is _UNSAT


@pytest.mark.parametrize("hdr", [
    "", "chunks=0-9", "bytes=", "bytes=abc", "bytes=1-2,3-4", "chars=0-9",
])
def test_ranges_that_should_be_ignored(hdr):
    assert _parse_range(hdr, 256) is None


def test_range_request_returns_206_slice(clients, home_with_files):
    login(clients["bob"], "bob")
    r = clients["bob"].get("/api/files/download", params={"path": "blob.bin"},
                           headers={"Range": "bytes=10-19"})
    assert r.status_code == 206
    assert r.content == bytes(range(10, 20))
    assert r.headers["content-range"] == "bytes 10-19/256"
    assert r.headers["content-length"] == "10"
    assert r.headers["accept-ranges"] == "bytes"


def test_range_request_beyond_end_is_416(clients, home_with_files):
    login(clients["bob"], "bob")
    r = clients["bob"].get("/api/files/download", params={"path": "blob.bin"},
                           headers={"Range": "bytes=9999-"})
    assert r.status_code == 416
    assert r.headers["content-range"] == "bytes */256"


def test_multi_range_falls_back_to_full_body(clients, home_with_files):
    login(clients["bob"], "bob")
    r = clients["bob"].get("/api/files/download", params={"path": "blob.bin"},
                           headers={"Range": "bytes=0-9,20-29"})
    assert r.status_code == 200
    assert r.content == bytes(range(256))


def test_head_request_sends_no_body(tmp_path):
    """The route only accepts GET, so HEAD is exercised on the class itself.

    A player or a crawler may still send one wherever HEAD *is* routed, and the
    contract is: advertise the length, send nothing, close the descriptor.
    """
    f = tmp_path / "a.bin"
    f.write_bytes(bytes(range(256)))
    sent = []

    async def send(msg):
        sent.append(msg)

    for method, want_body in (("HEAD", b""), ("GET", bytes(range(256)))):
        sent.clear()
        fd = _open_ro(f)
        st = os.fstat(fd)
        resp = fileserv.FdFileResponse(
            fd, st, "application/octet-stream", {}, None)
        asgi_call(resp, {"type": "http", "method": method}, send)
        start = next(m for m in sent if m["type"] == "http.response.start")
        assert start["status"] == 200
        hdr = asgi_headers(start)
        assert hdr["content-length"] == "256"
        assert hdr["accept-ranges"] == "bytes"
        body = b"".join(m["body"] for m in sent
                        if m["type"] == "http.response.body")
        assert body == want_body
        assert _is_closed(fd), f"fd {fd} left open on {method}"


def test_range_response_headers_on_a_head_request(tmp_path):
    """A HEAD with a Range still reports the slice it *would* send."""
    f = tmp_path / "a.bin"
    f.write_bytes(bytes(range(256)))
    sent = []

    async def send(msg):
        sent.append(msg)

    fd = _open_ro(f)
    resp = fileserv.FdFileResponse(fd, os.fstat(fd), None, {}, "bytes=10-19")
    asgi_call(resp, {"type": "http", "method": "HEAD"}, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 206
    hdr = asgi_headers(start)
    assert hdr["content-length"] == "10"
    assert hdr["content-range"] == "bytes 10-19/256"
    body = b"".join(m["body"] for m in sent
                    if m["type"] == "http.response.body")
    assert body == b""
    assert _is_closed(fd)


def test_non_http_scope_still_closes_the_fd(tmp_path):
    """Nothing may be left dangling when there is no body to stream."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "websocket.disconnect"}

    fd = _open_ro(f)
    resp = fileserv.FdFileResponse(fd, os.fstat(fd), None, {}, None)
    asgi_call(resp, {"type": "websocket"}, send, receive)
    assert _is_closed(fd)


def test_descriptor_is_closed_when_the_client_goes_away(tmp_path):
    """A send() that raises mid-body must not leak the descriptor."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"z" * (fileserv.CHUNK * 3))

    async def send(msg):
        if msg["type"] == "http.response.body" and msg.get("more_body"):
            raise ConnectionError("client vanished")

    fd = _open_ro(f)
    resp = fileserv.FdFileResponse(fd, os.fstat(fd), None, {}, None)
    with pytest.raises(ConnectionError):
        asgi_call(resp, {"type": "http", "method": "GET"}, send)
    assert _is_closed(fd)


def _is_closed(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError:
        return True
    return False


def asgi_headers(start_msg) -> dict[str, str]:
    """Response headers of an ``http.response.start`` message, as text.

    ASGI carries them as byte pairs, which makes raw ``dict(...)`` lookups miss
    every key — decode once so the assertions read like HTTP.
    """
    return {k.decode("latin-1"): v.decode("latin-1")
            for k, v in start_msg["headers"]}


async def _never_called():
    raise AssertionError("receive() should not be needed to stream a file")


def asgi_call(response, scope, send, receive=None):
    """Drive an ASGI response object to completion (no event loop in this suite).

    ``receive`` defaults to a callable that fails loudly: streaming a file body
    must never consult it, and the websocket-denial branch is the one place
    that does, so it passes a real stub instead.
    """
    import anyio

    async def _main():
        await response(scope, receive or _never_called, send)

    anyio.run(_main)


# ---------- fd hygiene ----------

def test_no_descriptor_leaks(clients, home_with_files):
    """Every request must close exactly the descriptor it opened."""
    opened, closed = [], []
    real_close = os.close

    def spy_close(fd):
        closed.append(fd)
        return real_close(fd)

    real_open = os.open
    def spy_open(*a, **k):
        fd = real_open(*a, **k)
        opened.append(fd)
        return fd

    login(clients["bob"], "bob")
    b = clients["bob"]
    monkey_os_close = spy_close
    os.close = monkey_os_close
    os.open = spy_open
    try:
        for _ in range(3):
            b.get("/api/files/download", params={"path": "blob.bin"})
            b.get("/api/files/preview", params={"path": "pic.png"})
            b.get("/api/files/download", params={"path": "blob.bin"},
                  headers={"Range": "bytes=0-9"})
            b.get("/api/files/download", params={"path": "blob.bin"},
                  headers={"Range": "bytes=9999-"})
    finally:
        os.close = real_close
        os.open = real_open
    # safepath opens directories along the walk too, so compare per-request
    # balance rather than exact counts: nothing may be left behind.
    leaked = [fd for fd in opened if fd not in closed]
    assert not leaked, f"leaked fds: {leaked}"


def test_range_helper_is_pure():
    """Parsing must not touch the fd or the filesystem at all."""
    assert fileserv._parse_range("bytes=0-1", 100) == (0, 2)
    assert fileserv._parse_range("bytes=nope", 100) is None


# ---------- the race the fd streaming exists to close ----------

@pytest.mark.skipif(os.name == "nt",
                    reason="Windows refuses to unlink a file that has an open "
                           "handle (WinError 32), so the inode swap below "
                           "cannot be staged")
def test_delivery_streams_from_the_descriptor_not_the_name(clients,
                                                           home_with_files,
                                                           monkeypatch):
    """Delivery must serve the descriptor safepath opened, never re-open by name.

    ``FileResponse(path)`` resolves the name at construction and opens it *again*
    when the body is sent. In between, the slot user who owns the tree can
    replace the entry, and the daemon — which runs as root — serves whatever the
    name now resolves to. Streaming from the already-open descriptor leaves no
    second look-up to race.

    The proof is a swap, not a descriptor count. Counting ``os.open`` calls is
    backend-specific: the anchored backend legitimately opens a directory
    descriptor per hop, so it reports more than the portable fallback — and a
    fixed count of one happened to hold only on the fallback, which opens by
    name. That is exactly the behaviour this test exists to forbid, so asserting
    it proved nothing on Windows and failed on the deployment target.

    Instead the file is unlinked and recreated — a *new inode* — the instant
    safepath returns the descriptor. A re-open by name would serve the
    replacement; the held descriptor still refers to the original inode and its
    original bytes.
    """
    from app import files as F

    calls = []
    real = F.open_read_fd

    def spy(root, rel):
        calls.append(str(rel))
        fd = real(root, rel)
        # The owner's move: swap the entry for a different inode. Truncating in
        # place would not do — that keeps the same inode, so the descriptor we
        # just handed back would see the new bytes too and the test would prove
        # nothing either way.
        victim = os.path.join(str(root), str(rel))
        os.unlink(victim)
        with open(victim, "wb") as fh:
            fh.write(b"SWAPPED-BY-THE-OWNER")
        return fd

    monkeypatch.setattr(F, "open_read_fd", spy)
    login(clients["bob"], "bob")
    r = clients["bob"].get("/api/files/download", params={"path": "blob.bin"})

    assert calls == ["blob.bin"]
    assert r.status_code == 200
    assert r.content == bytes(range(256)), \
        "served the swapped-in file instead of the open descriptor"
    # size came from fstat(fd), not from a fresh stat of the path
    assert r.headers["content-length"] == "256"


def test_delivery_never_reopens_the_target_by_name(clients, home_with_files,
                                                   monkeypatch):
    """No second name resolution of the target after safepath hands back an fd.

    The portable companion to the inode-swap test above, and the one that runs
    everywhere: it states the same property directly instead of through its
    consequence. Every ``os.open`` and builtin ``open`` is recorded, but only
    ones that name the target *after* the descriptor was handed back count —
    safepath's own opens (including the fallback backend's single open-by-name,
    and the anchored backend's per-hop directory descriptors) happen before that
    point and are not what this is about.
    """
    import builtins

    from app import files as F

    handed_back: list[int] = []
    late: list[tuple[str, str]] = []
    real_read_fd = F.open_read_fd
    real_os_open = os.open
    real_builtin_open = builtins.open

    def names_target(file) -> bool:
        try:
            p = os.fspath(file)
        except TypeError:
            return False          # an fd, a file object, an int — not a path
        return isinstance(p, str) and os.path.basename(p) == "blob.bin"

    def spy_read_fd(root, rel):
        fd = real_read_fd(root, rel)
        handed_back.append(fd)
        return fd

    def spy_os_open(file, *a, **k):
        if handed_back and names_target(file):
            late.append(("os.open", os.fspath(file)))
        return real_os_open(file, *a, **k)

    def spy_builtin_open(file, *a, **k):
        if handed_back and names_target(file):
            late.append(("open", os.fspath(file)))
        return real_builtin_open(file, *a, **k)

    monkeypatch.setattr(F, "open_read_fd", spy_read_fd)
    monkeypatch.setattr(os, "open", spy_os_open)
    monkeypatch.setattr(builtins, "open", spy_builtin_open)

    login(clients["bob"], "bob")
    r = clients["bob"].get("/api/files/download", params={"path": "blob.bin"})

    assert r.status_code == 200 and r.content == bytes(range(256))
    assert len(handed_back) == 1, handed_back
    assert late == [], f"re-opened by name during delivery: {late}"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlink_outside_the_root_is_refused(clients, env):
    """Following a slot's symlink must not hand root a file outside its home."""
    home = Path(env["homes"]["bob"])
    secret = home.parent / "host-secret.txt"
    secret.write_text("root-only")
    link = home / "link.txt"
    try:
        os.symlink(str(secret), str(link))
    except OSError as e:                          # unprivileged Windows/Linux
        pytest.skip(f"cannot create symlink here: {e}")
    login(clients["bob"], "bob")
    b = clients["bob"]
    assert b.get("/api/files/download", params={"path": "link.txt"}
                 ).status_code == 400
    assert b.get("/api/files/preview", params={"path": "link.txt"}
                 ).status_code in (400, 415)
    assert "root-only" not in b.get(
        "/api/files/read", params={"path": "link.txt"}).text


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlink_inside_the_root_still_works(clients, env):
    """Legitimate in-home links keep working — only escapes are refused."""
    home = Path(env["homes"]["bob"])
    (home / "real.txt").write_text("hello")
    link = home / "alias.txt"
    try:
        os.symlink("real.txt", str(link))
    except OSError as e:
        pytest.skip(f"cannot create symlink here: {e}")
    login(clients["bob"], "bob")
    r = clients["bob"].get("/api/files/download", params={"path": "alias.txt"})
    assert r.status_code == 200
    assert r.content == b"hello"
