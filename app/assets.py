"""Content-hash cache busting for the SPA shell.

``static/index.html`` used to carry a hand-maintained ``?v=23`` on every script
and stylesheet. That number has to be bumped by a human, on every asset change,
and forgetting it pins users to stale JS for as long as the browser's cache
allows — after a security fix, which is exactly when it matters most.

Here the version is derived from the file's own bytes instead. Editing an asset
changes its URL automatically; nothing has to be remembered.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

# `static/js/00-core.js?v=23` or `static/style.css?v=23` — the placeholder
# digits are irrelevant, they are replaced wholesale.
_ASSET_RE = re.compile(r"""(["'(])(static/[^"'()?]+)\?v=([^"'()]*)(["')])""")

_VERSION_LEN = 12


def _version(path: Path) -> str:
    """A short content hash, or ``dev`` when the file is missing.

    A missing asset must not turn into a 500 on the shell — the browser will
    report the failed script fetch, which is the more useful signal.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return "dev"
    return hashlib.sha256(data).hexdigest()[:_VERSION_LEN]


class ShellRenderer:
    """Renders ``index.html`` with hashed asset versions, cached by mtime.

    Hashing eleven files per request is waste, but caching the rendered HTML
    forever is wrong the moment someone edits an asset — and on a dev box with
    no reload, a stale shell is what makes a frontend change appear to do
    nothing. So the cache is keyed on every input's ``(mtime, size)``: touch a
    file and the next request re-renders.
    """

    def __init__(self, root: Path):
        self._root = Path(root)
        self._index = self._root / "static" / "index.html"
        self._cached_key: tuple | None = None
        self._cached_html: str = ""

    def _fingerprint(self, rel: str) -> tuple:
        p = self._root / rel
        try:
            st = p.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return (-1, -1)

    def render(self) -> str:
        """The shell HTML with every ``?v=`` replaced by a content hash."""
        try:
            html = self._index.read_text(encoding="utf-8")
        except OSError as e:
            raise OSError(f"cannot read SPA shell: {e}") from e

        rels = sorted({m.group(2) for m in _ASSET_RE.finditer(html)})
        key = (self._fingerprint("static/index.html"),
               tuple((r, self._fingerprint(r)) for r in rels))
        if key == self._cached_key:
            return self._cached_html

        versions = {r: _version(self._root / r) for r in rels}

        def sub(m: re.Match[str]) -> str:
            return f"{m.group(1)}{m.group(2)}?v={versions[m.group(2)]}{m.group(4)}"

        out = _ASSET_RE.sub(sub, html)
        self._cached_key, self._cached_html = key, out
        return out

    def versioned(self, rel: str) -> str:
        """The current version string for one asset (``static/...``)."""
        return _version(self._root / rel)
