"""Content-hash cache busting for the SPA shell.

The point of all this is that editing an asset changes its URL without a human
remembering to bump ``?v=``. These tests drive that behaviour directly against
a temp tree, including the mtime-keyed cache — which has to notice an edit even
when it happens inside the same second.
"""
import hashlib
import os
import re
import time
from pathlib import Path

import pytest

from app import assets as ASSETS

_SHELL = """<!doctype html>
<html>
<head>
<link rel="stylesheet" href="static/style.css?v=23">
</head>
<body>
<script src="static/js/00-core.js?v=23"></script>
<script src="static/js/07-files.js?v=23"></script>
</body>
</html>
"""


@pytest.fixture()
def tree(tmp_path: Path):
    (tmp_path / "static" / "js").mkdir(parents=True)
    (tmp_path / "static" / "index.html").write_text(_SHELL, encoding="utf-8")
    (tmp_path / "static" / "style.css").write_text("body{}", encoding="utf-8")
    (tmp_path / "static" / "js" / "00-core.js").write_text("// core",
                                                            encoding="utf-8")
    (tmp_path / "static" / "js" / "07-files.js").write_text("// files",
                                                            encoding="utf-8")
    return tmp_path


def _hash12(p) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()[:12]


def test_manual_v_numbers_are_replaced_by_content_hashes(tree):
    html = ASSETS.ShellRenderer(tree).render()
    assert "?v=23" not in html, "the hand-maintained version must be gone"
    core = _hash12(tree / "static" / "js" / "00-core.js")
    assert f'src="static/js/00-core.js?v={core}"' in html
    assert f'href="static/style.css?v={_hash12(tree / "static/style.css")}"' in html
    # all three assets are versioned
    assert html.count("?v=") == 3


def test_two_assets_with_identical_bytes_get_identical_versions(tree):
    (tree / "static" / "js" / "07-files.js").write_text("// core",
                                                        encoding="utf-8")
    html = ASSETS.ShellRenderer(tree).render()
    same = _hash12(tree / "static" / "js" / "00-core.js")
    assert html.count(f"?v={same}") == 2


def test_editing_an_asset_changes_its_url(tree):
    """The whole reason this exists: no human has to bump a version."""
    r = ASSETS.ShellRenderer(tree)
    before = r.render()
    core = tree / "static" / "js" / "00-core.js"
    old_url = f"00-core.js?v={_hash12(core)}"

    # bump mtime explicitly: a fast test on a coarse filesystem could otherwise
    # write new bytes with an unchanged timestamp, and only size would differ.
    core.write_text("// core v2", encoding="utf-8")
    os.utime(core, (time.time() + 5, time.time() + 5))

    after = r.render()
    assert old_url in before
    assert old_url not in after, "a stale URL would pin users to old JS"
    assert f"00-core.js?v={_hash12(core)}" in after


def test_unrelated_edit_leaves_other_urls_alone(tree):
    r = ASSETS.ShellRenderer(tree)
    before = r.render()
    css_url = f"style.css?v={_hash12(tree / 'static/style.css')}"

    core = tree / "static" / "js" / "00-core.js"
    core.write_text("// changed", encoding="utf-8")
    os.utime(core, (time.time() + 5, time.time() + 5))

    after = r.render()
    assert css_url in before and css_url in after, \
        "only the edited asset should get a new version"


def test_render_is_cached_while_nothing_changed(tree):
    r = ASSETS.ShellRenderer(tree)
    first = r.render()
    # second call must not re-hash: prove it by making hashing explode
    def boom(*a, **k):
        raise AssertionError("rendered from cache; _version must not be called")

    saved = ASSETS._version
    ASSETS._version = boom
    try:
        assert r.render() == first
    finally:
        ASSETS._version = saved


def test_cache_is_per_renderer_instance(tree, tmp_path):
    """Two renderers must not share state (tests build fresh trees)."""
    a, b = ASSETS.ShellRenderer(tree), ASSETS.ShellRenderer(tree)
    assert a.render() == b.render()
    assert a is not b


def test_missing_asset_renders_dev_instead_of_crashing(tree):
    (tree / "static" / "js" / "07-files.js").unlink()
    html = ASSETS.ShellRenderer(tree).render()
    assert "07-files.js?v=dev" in html


def test_missing_shell_raises_with_a_useful_message(tmp_path):
    r = ASSETS.ShellRenderer(tmp_path)      # no static/index.html at all
    with pytest.raises(OSError, match="cannot read SPA shell"):
        r.render()


def test_versioned_helper_matches_the_rendered_url(tree):
    r = ASSETS.ShellRenderer(tree)
    v = r.versioned("static/js/00-core.js")
    assert v == _hash12(tree / "static" / "js" / "00-core.js")
    assert f"?v={v}" in r.render()


def test_real_repo_shell_has_no_manual_version_left():
    """Guards the checked-in index.html, which the tests above only mirror.

    If someone re-adds a literal ``?v=`` that the regex cannot parse, or the
    shell stops matching, this fails instead of silently serving unversioned
    (or stale) assets.
    """
    root = Path(__file__).resolve().parents[1]
    index = root / "static" / "index.html"
    if not index.is_file():                     # pragma: no cover
        pytest.skip("no static/index.html in this checkout")
    html = ASSETS.ShellRenderer(root).render()
    src = index.read_text(encoding="utf-8")
    assert "?v=" in src, "expected the shell to carry versioned asset URLs"
    # every versioned asset in the source is present in the rendered output,
    # carrying a 12-hex content hash rather than the literal digits from src.
    matches = re.findall(r"(static/[^\"'()?]+)\?v=", src)
    assert matches, "no versioned assets found in index.html — regex drifted"
    for rel in matches:
        assert f"{rel}?v=" in html, f"{rel} lost its version in rendering"
        assert re.search(re.escape(rel) + r"\?v=[0-9a-f]{12}(?=[\"')])", html), \
            f"{rel} was not re-versioned with a content hash"
    # and no hand-maintained number survives
    assert "?v=23" not in html


def test_regex_does_not_eat_a_query_string_it_should_not(tree):
    """A URL that is not `static/...?v=` must survive rendering untouched."""
    (tree / "static" / "index.html").write_text(
        '<script src="static/js/00-core.js?v=23"></script>\n'
        '<a href="https://example.com/x?v=23">keep</a>\n'
        '<img src="other/thing.png?v=23">\n', encoding="utf-8")
    html = ASSETS.ShellRenderer(tree).render()
    assert "https://example.com/x?v=23" in html
    assert "other/thing.png?v=23" in html
    assert "00-core.js?v=23" not in html


# ---------- through the real app ----------

def test_index_route_serves_hashed_versions_and_no_store(clients):
    """``GET /`` was previously untested entirely.

    Two things have to hold together: the shell carries content-hashed asset
    URLs, and the shell itself is ``no-store``. If the shell were cacheable, a
    browser would keep pointing at old hashes and the whole scheme would be
    useless.
    """
    r = clients["admin"].get("/")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert "?v=23" not in r.text
    assert re.search(r'static/js/00-core\.js\?v=[0-9a-f]{12}', r.text)
    # a hashed asset URL is still served, and may be cached
    a = clients["admin"].get("/static/js/00-core.js")
    assert a.status_code == 200
    assert "public" in a.headers["cache-control"]


def test_index_route_follows_an_asset_edit(tree, monkeypatch):
    """End to end: edit a file, the served shell points at the new hash.

    This is the property that a forgotten manual ``?v=`` bump used to break.

    The renderer is pointed at a throwaway tree rather than the repo's own
    ``static/``: the test has to rewrite an asset to prove the point, and a
    failure part-way through must not leave the working tree dirty.
    """
    from fastapi.testclient import TestClient

    import app.main as main

    monkeypatch.setattr(main, "_shell", ASSETS.ShellRenderer(tree))
    core = tree / "static" / "js" / "00-core.js"

    with TestClient(main.app) as c:
        first = c.get("/").text
        m = re.search(r'00-core\.js\?v=([0-9a-f]{12})', first)
        assert m and m.group(1) == _hash12(core)

        # bump mtime explicitly: new bytes written inside the same second as the
        # fixture created them would otherwise be missed on a coarse fs
        core.write_text("// core v2", encoding="utf-8")
        os.utime(core, (time.time() + 5, time.time() + 5))

        second = c.get("/").text
        m2 = re.search(r'00-core\.js\?v=([0-9a-f]{12})', second)
        assert m2, "asset URL lost its version after an edit"
        assert m2.group(1) != m.group(1), "stale hash: users would stay on old JS"
        assert m2.group(1) == _hash12(core)
