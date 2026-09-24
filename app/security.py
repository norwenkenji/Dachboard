"""HTTP hardening: security headers and safe delivery of user-owned bytes.

Two problems live here.

**Headers.** The panel is a single-origin app whose session rides an
``HttpOnly`` cookie, and it is normally reached through a tunnel or nginx. Any
document rendered on that origin inherits the session, so a user-controlled
file served as HTML would be a full account takeover. The middleware below
sets a strict CSP plus ``nosniff``/``frame-ancestors`` on every response.

**User bytes.** Slot users can upload anything into their home, so the panel
must never hand those bytes back as an *active* document on its own origin:

* :func:`attachment_headers` — force a download. No MIME sniffing, no inline
  rendering, so a stored ``evil.html`` cannot execute on the panel origin.
* :func:`preview_headers` — inline, but under ``CSP: sandbox``, which makes the
  response a unique origin. Its scripts cannot read panel state, and
  ``SameSite=Lax`` keeps the session cookie off its requests.
"""
from __future__ import annotations

import re
from pathlib import Path

#: Types that must never be rendered inline, even sandboxed: they are the
#: obvious stored-XSS carriers and previewing them buys nothing.
ACTIVE_TYPES = {
    ".html", ".htm", ".xhtml", ".shtml", ".svg", ".js", ".mjs", ".cjs",
    ".xml", ".xsl", ".xsd", ".rss", ".atom", ".swf", ".jar",
}

#: Extensions the browser can render as a plain media resource.
#:
#: This is the single source of truth for what may be previewed inline: the
#: ``mediaKind()`` map in ``static/js/07-files.js`` mirrors it, and a type that
#: is not listed here is refused with 415 and offered as a download instead.
MEDIA_TYPES = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    ".ico": "image/x-icon", ".avif": "image/avif",
    ".mp4": "video/mp4", ".webm": "video/webm", ".mov": "video/quicktime",
    ".mkv": "video/x-matroska", ".avi": "video/x-msvideo",
    ".mp3": "audio/mpeg", ".wav": "audio/wav", ".ogg": "audio/ogg",
    ".m4a": "audio/mp4", ".flac": "audio/flac",
    ".pdf": "application/pdf",
    ".txt": "text/plain; charset=utf-8",
    ".csv": "text/plain; charset=utf-8",
    ".json": "text/plain; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
}

OCTET_STREAM = "application/octet-stream"

#: A preview must stay iframe-able by the SPA itself (the PDF viewer is loaded
#: in one) and by nobody else. ``frame-ancestors`` is the CSP-level control;
#: the route also sends ``X-Frame-Options: SAMEORIGIN`` for older browsers.
_FRAME_SELF = "frame-ancestors 'self'"

#: Chrome renders PDFs through its internal plugin, which ``object-src`` gates:
#: a bare ``default-src 'none'`` would block the viewer entirely.
_PDF_CSP = f"default-src 'none'; object-src 'self'; {_FRAME_SELF}"

#: Images, media and plain text are resources, not documents: nothing in them
#: can run script, so the strictest policy that still displays them is right.
#:
#: Deliberately *not* ``sandbox``. A sandboxed response becomes a unique origin,
#: and Chrome's PDF plugin refuses to load in one — so ``CSP: sandbox`` would
#: trade a working PDF preview for no real gain here. The actual guarantees for
#: this endpoint are structural: a fixed extension allow-list (:data:`ACTIVE_TYPES`
#: is refused outright), a forced non-sniffable MIME type, and ``nosniff``.
_PLAIN_CSP = f"default-src 'none'; {_FRAME_SELF}"

_CSP_PARTS = [
    "default-src 'self'",
    # Every script is a versioned external file; there are no inline handlers
    # and no eval anywhere in static/js, so script-src can stay strict.
    "script-src 'self'",
    # Inline style *attributes* are used by the SPA templates (meters, widths).
    # They cannot execute code, so allowing them costs nothing.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "font-src 'self'",
    "connect-src 'self'",
    # The terminal iframe is same-origin: nginx proxies /term/<slot>/ to ttyd.
    "frame-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    # Stronger than X-Frame-Options and understood by every current browser.
    "frame-ancestors 'none'",
]

#: CSP for the SPA and its JSON APIs.
CONTENT_SECURITY_POLICY = "; ".join(_CSP_PARTS)


def security_headers(hsts: bool = True,
                     hsts_max_age: int = 31536000) -> dict[str, str]:
    """Headers every response should carry.

    Caching is deliberately absent: it depends on the path (versioned static
    assets may be cached, user bytes never), so the middleware decides it.

    HSTS is only honoured by browsers over HTTPS, which is exactly how the
    panel is reached through a tunnel — over plain loopback HTTP it is inert,
    so sending it unconditionally is safe and preloads the upgrade for anyone
    who later puts TLS in front.
    """
    h = {
        "Content-Security-Policy": CONTENT_SECURITY_POLICY,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=(), "
                              "payment=(), usb=()",
    }
    if hsts:
        h["Strict-Transport-Security"] = (
            f"max-age={hsts_max_age}; includeSubDomains")
    return h


def _filename_header(name: str) -> str:
    """RFC 6266 Content-Disposition value for a download of ``name``."""
    clean = re.sub(r'[\\/]', "_", name or "download").strip() or "download"
    # A quote or backslash inside the value would break out of the header.
    clean = clean.replace("\\", "\\\\").replace('"', '\\"')
    clean = clean.replace("\r", "").replace("\n", "")
    return f'attachment; filename="{clean}"'


def attachment_headers(name: str) -> dict[str, str]:
    """Headers that force ``name`` to download instead of render."""
    return {
        "Content-Type": OCTET_STREAM,
        "Content-Disposition": _filename_header(name),
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox",
    }


def preview_headers(name: str) -> tuple[str, dict[str, str]] | None:
    """(media_type, headers) for a safe inline preview, or ``None``.

    ``None`` means "do not preview this": unknown types and active-content
    types must go through :func:`attachment_headers` instead.

    The returned headers make the resource displayable but inert: a locked-down
    CSP with no script source, ``nosniff`` so the declared type is the only one
    honoured, and framing restricted to the panel itself.
    """
    ext = Path(name or "").suffix.lower()
    if ext in ACTIVE_TYPES:
        return None
    media = MEDIA_TYPES.get(ext)
    if not media:
        return None
    csp = _PDF_CSP if ext == ".pdf" else _PLAIN_CSP
    return media, {
        "Content-Disposition": f'inline; filename="{_inline_name(name)}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": csp,
        # The SPA embed previews in an <iframe>; DENY would break that, and a
        # wildcard would let any site frame user bytes on this origin.
        "X-Frame-Options": "SAMEORIGIN",
    }


def _inline_name(name: str) -> str:
    clean = re.sub(r'[\\/]', "_", name or "file").strip() or "file"
    return (clean.replace("\\", "\\\\").replace('"', '\\"')
            .replace("\r", "").replace("\n", ""))


_FORWARDED_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+$")


def client_ip(request, cfg: dict | None = None) -> str:
    """Best-guess client address for rate limiting.

    The daemon sits behind nginx, so ``request.client.host`` is always the
    proxy (127.0.0.1). Trusting a spoofable header blindly would let one
    attacker hand out unlimited buckets, so only the rightmost ``hops``
    entries of ``X-Forwarded-For`` are used — the ones the proxy itself
    appended. ``hops`` defaults to 1 (a single local reverse proxy); set it to
    the real chain length when a tunnel terminates in front of nginx.
    """
    cfg = cfg or {}
    direct = getattr(getattr(request, "client", None), "host", "") or "?"
    if not cfg.get("trust_forwarded_for", True):
        return direct
    raw = request.headers.get("x-forwarded-for", "")
    if not raw:
        return direct
    hops = max(1, int(cfg.get("forwarded_hops", 1)))
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if len(parts) < hops:
        return direct
    cand = parts[-hops]
    # Never let a malformed or bare-IPv6-with-port value become a bucket key.
    if cand.startswith("[") and "]" in cand:
        cand = cand[1:cand.index("]")]
    return cand if _FORWARDED_RE.match(cand) else direct
