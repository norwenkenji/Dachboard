import pytest

from app import files as F


@pytest.fixture()
def root(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.txt").write_text("hello")
    (tmp_path / "top.txt").write_text("top")
    return tmp_path


def test_list(root):
    rows = F.list_dir(root, "")
    names = [r["name"] for r in rows]
    assert "sub" in names and "top.txt" in names
    dirs = [r for r in rows if r["dir"]]
    assert {d["name"] for d in dirs} == {"sub"}


def test_list_sub(root):
    rows = F.list_dir(root, "sub")
    assert len(rows) == 1
    assert rows[0]["name"] == "a.txt" and not rows[0]["dir"]
    assert rows[0]["size"] == 5


def test_escape_blocked(root):
    for bad in ("..", "../x", "sub/../../x", "/etc/passwd"):
        with pytest.raises(PermissionError):
            F.resolve(root, bad)


def test_dot_ok(root):
    assert F.resolve(root, "") == root.resolve()
    assert F.resolve(root, ".") == root.resolve()


def test_read_write_roundtrip(root):
    F.write_text(root, "new/deep.txt", "data123")
    assert F.read_text(root, "new/deep.txt") == "data123"


def test_read_too_large(root, tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * (F.MAX_FILE + 1))
    with pytest.raises(ValueError):
        F.read_text(tmp_path, "big.bin")


def test_mkdir_remove(root):
    F.mkdir(root, "d1/d2")
    assert (root / "d1" / "d2").is_dir()
    (root / "f.txt").write_text("x")
    F.remove(root, "f.txt")
    assert not (root / "f.txt").exists()
    F.remove(root, "d1")
    assert not (root / "d1").exists()


def test_disk_usage(root):
    assert F.disk_usage(root) == 8
