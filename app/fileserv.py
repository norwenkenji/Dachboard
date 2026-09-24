"""Race-free file delivery over an already-open descriptor.

Why this exists
---------------
``starlette.responses.FileResponse`` opens its ``path`` **by name** when the
body is sent, not when the response is constructed. The file routes validate a
user path through the anchored walk in :mod:`app.safepath` first — and between
that validation and the open, the slot user who owns the tree can swap a path
component for a symlink. The daemon runs as root, so the swap turns "download a
file from my home" into "read /etc/shadow".

Opening once through safepath and streaming from that descriptor has no window
at all: the fd refers to the inode that was validated, whatever happens to the
name afterwards.

Range support is kept (single range only) because ``<video>`` and ``<audio>``
seek with it; a multi-range request falls back to the whole body, which is a
legal answer.
"""
from __future__ import annotations

import asyncio
import os
from contextlib import suppress
from email.utils import formatdate

from starlette.responses import Response
from starlette.types import Scope, Send

#: Read size per hop. Large enough to keep syscalls down on a tunnel, small
#: enough that one slow client cannot pin much memory.
CHUNK = 64 * 1024

#: Sentinel: the request named a range that cannot be satisfied -> 416.
_UNSAT = object()


def _parse_range(header: str, size: int):
    """Parse a ``Range`` header into ``(start, end_exclusive)``.

    Returns ``_UNSAT`` for an unsatisfiable range, or ``None`` when the header
    should simply be ignored (malformed, or multi-range — a full body is a
    valid response to a multi-range request and much simpler to produce).
    """
    if header[:6].lower() != "bytes=":
        return None
    spec = header[6:].strip()
    if not spec or "," in spec:
        return None
    first, _, last = spec.partition("-")
    try:
        if not first:
            # suffix range: the last N bytes
            n = int(last)
            if n <= 0:
                return _UNSAT
            return max(0, size - n), size
        start = int(first)
        end = size if not last else int(last) + 1     # inclusive -> exclusive
    except ValueError:
        return None                                   # garbage: ignore it
    if start < 0 or start >= size or end <= start:
        return _UNSAT
    return start, min(end, size)


class FdFileResponse(Response):
    """Streams an open descriptor, then closes it exactly once.

    The caller transfers ownership of ``fd``: this object closes it whatever
    happens, including a client that disconnects mid-body.
    """

    def __init__(self, fd: int, st: os.stat_result, media_type: str | None,
                 headers: dict[str, str],
                 range_header: str | None = None) -> None:
        self.fd = fd
        size = st.st_size
        self._size = size
        self._range: tuple[int, int] | None = None
        extra = dict(headers)
        status = 200
        parsed = _parse_range(range_header, size) if range_header else None
        if parsed is _UNSAT:
            status = 416
            self._length = 0
            extra["Content-Range"] = f"bytes */{size}"
        elif parsed is not None:
            status = 206
            self._range = parsed
            self._length = parsed[1] - parsed[0]
            extra["Content-Range"] = (
                f"bytes {parsed[0]}-{parsed[1] - 1}/{size}")
        else:
            self._length = size
        extra["Accept-Ranges"] = "bytes"
        extra["Content-Length"] = str(self._length)
        # A player may re-request a byte range it saw before; these let it
        # notice the file changed instead of stitching two versions together.
        extra.setdefault("Last-Modified", formatdate(st.st_mtime, usegmt=True))
        super().__init__(content=None, status_code=status, headers=extra,
                         media_type=media_type)

    async def __call__(self, scope: Scope, receive, send: Send) -> None:
        if scope["type"] != "http":
            # nothing to stream; hand over and let the base class refuse
            with suppress(OSError):
                os.close(self.fd)
            await super().__call__(scope, receive, send)
            return
        header_only = scope["method"].upper() == "HEAD"
        try:
            await send({"type": "http.response.start",
                        "status": self.status_code,
                        "headers": self.raw_headers})
            start, end = self._range or (0, self._size)
            if header_only or end <= start:
                await send({"type": "http.response.body", "body": b"",
                            "more_body": False})
                return
            if start:
                await asyncio.to_thread(os.lseek, self.fd, start, os.SEEK_SET)
            sent = start
            while sent < end:
                chunk = await asyncio.to_thread(
                    os.read, self.fd, min(CHUNK, end - sent))
                if not chunk:
                    break                       # shrank under us: stop cleanly
                sent += len(chunk)
                await send({"type": "http.response.body", "body": chunk,
                            "more_body": sent < end})
            if sent < end:
                await send({"type": "http.response.body", "body": b"",
                            "more_body": False})
        finally:
            with suppress(OSError):
                os.close(self.fd)
