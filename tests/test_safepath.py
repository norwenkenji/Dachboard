"""safepath: the race-free file layer both backends must satisfy identically.

Parametrized over the backend. On Linux (CI) the kernel backend runs the real
anchored walk and the fallback runs resolve-and-verify; on platforms without
``dir_fd`` both collapse to the fallback, which still exercises the logic.
"""
import os
import sys
import zipfile

import pytest

from app import safepath as SP

BACKENDS = ["kernel", "fallback"]
WINDOWS = sys.platform == "win32"


@pytest.fixture(params=BACKENDS)
def backend(request, monkeypatch):
    """Pin the safepath backend for one test run."""
    want = request.param
    if want == "kernel" and not SP.KERNEL_CAPABLE:
        pytest.skip("kernel backend unavailable on this platform")
    monkeypatch.setattr(SP, "FORCE_FALLBACK", want == "fallback")
    return want


def _link_supported(tmp_path) -> bool:
    if WINDOWS:
        return False                    # needs Developer Mode / admin
    try:
        os.symlink(tmp_path / "x", tmp_path / "_probe_link")
    except OSError:
        return False
    (tmp_path / "_probe_link").unlink(missing_ok=True)
    return True


# --------------------------------------------------------------------------
# path splitting / escape guards
# --------------------------------------------------------------------------

def test_split_rejects_absolute():
    with pytest.raises(PermissionError):
        SP.split_rel("/etc/passwd")


def test_split_rejects_escape():
    for bad in ("..", "../x", "a/../../b"):
        with pytest.raises(PermissionError):
            SP.split_rel(bad)


def test_split_normalizes():
    assert SP.split_rel("a/./b//c") == ["a", "b", "c"]
    assert SP.split_rel("") == []


def test_resolve_blocks_escape(tmp_path):
    for bad in ("..", "../x", "a/../../x", "/etc/passwd"):
        with pytest.raises(PermissionError):
            SP.resolve(tmp_path, bad)


def test_resolve_root_ok(tmp_path):
    assert SP.resolve(tmp_path, "") == tmp_path.resolve()


# --------------------------------------------------------------------------
# basic operations — identical contract on both backends
# --------------------------------------------------------------------------

def test_write_read_roundtrip(backend, tmp_path):
    SP.write_text(tmp_path, "deep/nested/f.txt", "payload")
    assert (tmp_path / "deep" / "nested" / "f.txt").read_text() == "payload"
    assert SP.read_text(tmp_path, "deep/nested/f.txt") == "payload"


def test_mkdir_and_list(backend, tmp_path):
    SP.mkdir(tmp_path, "d1/d2")
    SP.write_text(tmp_path, "d1/a.txt", "a")
    SP.write_text(tmp_path, "d1/b.txt", "b")
    rows = SP.list_dir(tmp_path, "d1")
    names = {r["name"]: r["dir"] for r in rows}
    assert names == {"a.txt": False, "b.txt": False, "d2": True}


def test_list_dirs_first_case_insensitive(backend, tmp_path):
    SP.mkdir(tmp_path, "Zdir")
    SP.write_text(tmp_path, "afile", "x")
    SP.write_text(tmp_path, "Bfile", "x")
    names = [r["name"] for r in SP.list_dir(tmp_path)]
    assert names == ["Zdir", "afile", "Bfile"]


def test_remove_file_and_tree(backend, tmp_path):
    SP.write_text(tmp_path, "f.txt", "x")
    SP.remove(tmp_path, "f.txt")
    assert not (tmp_path / "f.txt").exists()
    SP.write_text(tmp_path, "t/deep/g.txt", "y")
    SP.remove(tmp_path, "t")
    assert not (tmp_path / "t").exists()


def test_remove_refuses_root(backend, tmp_path):
    with pytest.raises(PermissionError):
        SP.remove(tmp_path, "")


def test_rename_moves(backend, tmp_path):
    SP.write_text(tmp_path, "src/a.txt", "data")
    SP.rename(tmp_path, "src/a.txt", "dst/b.txt")
    assert not (tmp_path / "src" / "a.txt").exists()
    assert (tmp_path / "dst" / "b.txt").read_text() == "data"


def test_rename_refuses_existing(backend, tmp_path):
    SP.write_text(tmp_path, "a.txt", "1")
    SP.write_text(tmp_path, "b.txt", "2")
    with pytest.raises(FileExistsError):
        SP.rename(tmp_path, "a.txt", "b.txt")


def test_copy_file_and_tree(backend, tmp_path):
    SP.write_text(tmp_path, "src/a.txt", "data")
    SP.write_text(tmp_path, "src/sub/b.txt", "nested")
    SP.copy(tmp_path, "src/a.txt", "out/a.txt")
    assert (tmp_path / "out" / "a.txt").read_text() == "data"
    SP.copy(tmp_path, "src", "tree")
    assert (tmp_path / "tree" / "sub" / "b.txt").read_text() == "nested"


def test_copy_refuses_existing(backend, tmp_path):
    SP.write_text(tmp_path, "a.txt", "1")
    SP.write_text(tmp_path, "b.txt", "2")
    with pytest.raises(FileExistsError):
        SP.copy(tmp_path, "a.txt", "b.txt")


def test_disk_usage_sums_files(backend, tmp_path):
    SP.write_bytes(tmp_path, "a.txt", b"x" * 10)
    SP.write_bytes(tmp_path, "sub/b.txt", b"y" * 5)
    assert SP.disk_usage(tmp_path) == 15


def test_read_too_large(backend, tmp_path):
    SP.write_bytes(tmp_path, "big.bin", b"x" * (SP.MAX_FILE + 1))
    with pytest.raises(ValueError):
        SP.read_text(tmp_path, "big.bin")


def test_open_read_fd_returns_readable_fd(backend, tmp_path):
    SP.write_text(tmp_path, "a.txt", "hello")
    fd = SP.open_read_fd(tmp_path, "a.txt")
    try:
        assert os.read(fd, 10) == b"hello"
    finally:
        os.close(fd)


# --------------------------------------------------------------------------
# ownership inheritance (so the slot's own shell can edit panel-written files)
# --------------------------------------------------------------------------

@pytest.mark.skipif(WINDOWS, reason="POSIX ownership")
def test_created_files_inherit_root_owner(backend, tmp_path):
    st_root = os.stat(tmp_path)
    SP.write_text(tmp_path, "a.txt", "x")
    SP.mkdir(tmp_path, "d")
    SP.write_text(tmp_path, "d/b.txt", "y")
    for rel in ("a.txt", "d", "d/b.txt"):
        st = os.stat(tmp_path / rel)
        assert (st.st_uid, st.st_gid) == (st_root.st_uid, st_root.st_gid)


# --------------------------------------------------------------------------
# symlink handling: in-home links work, out-of-home links are refused
# --------------------------------------------------------------------------

@pytest.mark.skipif(WINDOWS, reason="needs symlink privilege")
def test_inhome_symlink_is_followed_for_read(backend, tmp_path):
    if not _link_supported(tmp_path):
        pytest.skip("symlink() unavailable")
    SP.write_text(tmp_path, "real/secret.txt", "inside")
    os.symlink(tmp_path / "real" / "secret.txt", tmp_path / "link.txt")
    assert SP.read_text(tmp_path, "link.txt") == "inside"


@pytest.mark.skipif(WINDOWS, reason="needs symlink privilege")
def test_outside_symlink_read_refused(backend, tmp_path):
    if not _link_supported(tmp_path):
        pytest.skip("symlink() unavailable")
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("root-owned")
    home = tmp_path / "home"
    home.mkdir()
    os.symlink(outside, home / "escape.txt")
    try:
        with pytest.raises(PermissionError):
            SP.read_text(home, "escape.txt")
    finally:
        outside.unlink(missing_ok=True)


@pytest.mark.skipif(WINDOWS, reason="needs symlink privilege")
def test_outside_symlink_dir_component_refused(backend, tmp_path):
    """A symlinked *directory* mid-path must not carry the walk outside."""
    if not _link_supported(tmp_path):
        pytest.skip("symlink() unavailable")
    outside = tmp_path.parent / "outside-dir"
    outside.mkdir()
    (outside / "f.txt").write_text("root")
    home = tmp_path / "home"
    home.mkdir()
    os.symlink(outside, home / "linkdir")
    try:
        with pytest.raises(PermissionError):
            SP.write_text(home, "linkdir/pwn.txt", "x")
        assert not (outside / "pwn.txt").exists()
    finally:
        import shutil
        shutil.rmtree(outside, ignore_errors=True)


@pytest.mark.skipif(WINDOWS, reason="needs symlink privilege")
def test_disk_usage_does_not_follow_outside_link(backend, tmp_path):
    if not _link_supported(tmp_path):
        pytest.skip("symlink() unavailable")
    outside = tmp_path.parent / "big-outside.bin"
    outside.write_bytes(b"x" * 100000)
    home = tmp_path / "home"
    home.mkdir()
    SP.write_bytes(home, "small.txt", b"y" * 5)
    os.symlink(outside, home / "link.bin")
    try:
        assert SP.disk_usage(home) == 5
    finally:
        outside.unlink(missing_ok=True)


# --------------------------------------------------------------------------
# zip extraction guards
# --------------------------------------------------------------------------

def _zip(tmp_path, name: str, entries: dict) -> str:
    zp = tmp_path / name
    with zipfile.ZipFile(zp, "w") as z:
        for member, data in entries.items():
            z.writestr(member, data)
    return str(zp)


def test_unzip_ok_default_folder(backend, tmp_path):
    zp = _zip(tmp_path, "site.zip", {"app/main.py": "print(1)", "R.md": "hi"})
    written = SP.extract_zip(tmp_path, zp)
    assert set(written) == {"app/main.py", "R.md"}
    assert (tmp_path / "site" / "app" / "main.py").read_text() == "print(1)"
    assert (tmp_path / "site" / "R.md").read_text() == "hi"


def test_unzip_into(backend, tmp_path):
    zp = _zip(tmp_path, "s.zip", {"a.txt": "x"})
    SP.extract_zip(tmp_path, zp, into="deploy")
    assert (tmp_path / "deploy" / "a.txt").read_text() == "x"


def test_unzip_zip_slip_blocked(backend, tmp_path):
    zp = _zip(tmp_path, "evil.zip", {"../../escape.txt": "pwn"})
    with pytest.raises(PermissionError):
        SP.extract_zip(tmp_path, zp)
    assert not (tmp_path.parent / "escape.txt").exists()


def test_unzip_absolute_member_blocked(backend, tmp_path):
    zp = _zip(tmp_path, "abs.zip", {"/etc/pwn": "x"})
    with pytest.raises(PermissionError):
        SP.extract_zip(tmp_path, zp)


def test_unzip_symlink_member_blocked(backend, tmp_path):
    zp = tmp_path / "link.zip"
    zi = zipfile.ZipInfo("evil-link")
    zi.external_attr = (0o120000 << 16)     # symlink mode
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr(zi, "/etc/passwd")
    with pytest.raises(PermissionError, match="symlink"):
        SP.extract_zip(tmp_path, str(zp))


def test_unzip_too_many_entries(backend, tmp_path, monkeypatch):
    monkeypatch.setattr(SP, "MAX_ZIP_FILES", 2)
    zp = _zip(tmp_path, "many.zip", {f"f{i}.txt": "x" for i in range(5)})
    with pytest.raises(ValueError):
        SP.extract_zip(tmp_path, zp)


# --------------------------------------------------------------------------
# backend identity
# --------------------------------------------------------------------------

def test_backend_flag_matches_platform():
    assert SP.BACKEND in ("kernel", "fallback")
    if not SP.KERNEL_CAPABLE:
        assert SP.BACKEND == "fallback"


def test_kernel_capable_only_where_dirfd_exists():
    expected = bool(getattr(os, "O_NOFOLLOW", 0)) and os.open in os.supports_dir_fd
    assert SP.KERNEL_CAPABLE is (expected and os.scandir in os.supports_fd)
