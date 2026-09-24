"""Forensic trail for a daemon that runs as root.

This process creates and deletes linux users, writes ``/etc/systemd/system`` and
``/etc/nginx``, runs ``systemctl`` and ``useradd``, and edits files inside trees
it does not own. None of that leaves a trace anywhere else: SQLite only records
preset command runs, and journalctl gets whatever the caller happened to print.
After an incident there would be nothing to reconstruct.

So every security-relevant decision is written here — who, from where, what, and
whether it was allowed. Denials matter as much as successes: a burst of 403s on
``services_control`` is the interesting signal, not a bug report.

Deliberately absent: passwords, hashes, tokens, file contents, and command
output. An audit log that can be read by anyone with journal access must not
become a second credential store.

Transport is the stdlib ``logging`` logger ``dachboard.audit``. Under systemd it
lands in the journal; ``audit.file`` in config.yaml additionally appends it to a
file, which is what you want when the panel's own journal is the thing under
investigation.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

LOGGER_NAME = "dachboard.audit"

#: Written once per process: the daemon's identity belongs in the trail too.
BOOT = "boot"

_configured = False
_lock = threading.Lock()

#: Actions that mutate state or reveal host internals. Anything here should be
#: audited; the set exists so a reviewer can see the intended surface at a glance.
MUTATING = {
    "login", "login_failed", "logout", "password_change", "first_password",
    "setup", "user_create", "user_update", "user_delete", "password_reset",
    "token_create", "token_revoke",
    "slot_provision", "slot_wipe",
    "service_action", "container_action",
    "command_create", "command_update", "command_delete",
    "terminal_restart",
    "file_delete", "file_upload", "file_unzip", "file_write", "file_move",
}


def configure(cfg: dict | None = None) -> logging.Logger:
    """Wire the audit logger to the journal and, optionally, to a file.

    Idempotent and cheap, so ``main`` can call it on every start without
    tracking state. A misconfigured ``audit.file`` must never take the panel
    down: the file handler is skipped and the failure is reported on the main
    logger instead.
    """
    global _configured
    with _lock:
        log = logging.getLogger(LOGGER_NAME)
        if _configured:
            return log
        _configured = True
        log.setLevel(logging.INFO)
        log.propagate = False
        sec = (cfg or {}).get("audit", {}) or {}
        if not log.handlers:
            # No handler of our own: journald/systemd captures stderr, and a
            # bare StreamHandler keeps the module usable from tests and CLI.
            stderr = logging.StreamHandler()
            stderr.setFormatter(_Formatter())
            log.addHandler(stderr)
        path = str(sec.get("file") or "").strip()
        if path and bool(sec.get("file_enabled", True)):
            try:
                p = Path(path)
                p.parent.mkdir(parents=True, exist_ok=True)
                fh = logging.FileHandler(str(p), encoding="utf-8")
                fh.setFormatter(_Formatter())
                log.addHandler(fh)
            except OSError as e:
                logging.getLogger("dachboard").error(
                    "audit file %s unavailable: %s", path, e)
        return log


class _Formatter(logging.Formatter):
    """``key=value`` pairs: greppable by hand, parseable by a script."""

    def format(self, record: logging.LogRecord) -> str:
        parts = [f"ts={int(record.created)}", f"event={record.getMessage()}"]
        extra = getattr(record, "audit", None) or {}
        for k, v in extra.items():
            parts.append(f"{k}={_scalar(v)}")
        return " ".join(parts)


def _scalar(v: Any) -> str:
    """Render one audit field: quoted only when it must be.

    The empty case has to return early. Substituting ``'""'`` first and then
    running the "does it need quoting?" check would see the quotes it just
    inserted and escape them again, yielding ``"\\"\\""`` for a plain empty
    string.
    """
    s = "-" if v is None else str(v)
    if not s:
        return '""'
    if any(ch.isspace() for ch in s) or '"' in s:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def event(name: str, **fields: Any) -> None:
    """Record one audit event. Never raises — auditing must not break a request.

    ``None`` values are dropped so a caller can pass optional context
    unconditionally.
    """
    try:
        log = logging.getLogger(LOGGER_NAME)
        if not log.handlers:
            configure()
        clean = {k: v for k, v in fields.items() if v is not None}
        log.info(name, extra={"audit": clean})
    except Exception:                                    # pragma: no cover
        # An audit failure is worth a stderr line, never an exception: the
        # request it was describing is more important than the record.
        pass


def actor(user: dict | None) -> dict:
    """The identifying half of an audit record for ``user``.

    Machine tokens have no user id, so they are recorded by their subject name
    plus the ``via`` marker — "who" has to be answerable for a token too.

    Every key is prefixed with ``actor_`` (except ``actor`` itself) on purpose:
    call sites describe the *target* of an action with plain names like
    ``slot=``, ``unit=`` or ``container=``, and an unprefixed ``slot`` here
    would collide with those at the call boundary — a ``TypeError`` raised while
    building the audit line would take down the request it was meant to record.
    """
    if not user:
        return {"actor": "anonymous"}
    out = {"actor": user.get("login") or f"id:{user.get('id')}",
           "actor_via": user.get("via")}
    if user.get("is_admin"):
        out["actor_admin"] = 1
    if user.get("slot"):
        out["actor_slot"] = user["slot"]
    return {k: v for k, v in out.items() if v is not None}


def denied(user: dict | None, right: str, ip: str | None = None) -> None:
    """A rejected authorization attempt — the signal worth alerting on."""
    event("denied", right=right, ip=ip, **actor(user))
