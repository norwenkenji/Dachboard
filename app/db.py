"""SQLite schema + helpers. stdlib only."""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    pass_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    rights TEXT NOT NULL DEFAULT '{}',
    limits TEXT NOT NULL DEFAULT '{}',
    slot TEXT,
    must_change_pw INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    argv TEXT NOT NULL,
    run_as TEXT NOT NULL DEFAULT 'owner',
    allowed TEXT NOT NULL DEFAULT '[]',
    timeout_sec INTEGER NOT NULL DEFAULT 60,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cmd_id INTEGER,
    user_id INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    exit_code INTEGER,
    output TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS metrics (
    ts INTEGER PRIMARY KEY,
    cpu REAL, mem_used INTEGER, mem_total INTEGER,
    disk_used INTEGER, disk_total INTEGER, temp REAL, load1 REAL
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    rights TEXT NOT NULL DEFAULT '{}',
    slot TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS slots (
    slot TEXT PRIMARY KEY,
    port INTEGER UNIQUE NOT NULL,
    created_at INTEGER NOT NULL
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=30000")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init(path: str | Path) -> None:
    with closing(connect(path)) as con:
        con.executescript(SCHEMA)
        cols = {r[1] for r in con.execute("PRAGMA table_info(users)")}
        if "must_change_pw" not in cols:
            con.execute("ALTER TABLE users ADD COLUMN must_change_pw INTEGER NOT NULL DEFAULT 0")
        tcols = {r[1] for r in con.execute("PRAGMA table_info(api_tokens)")}
        if "slot" not in tcols:
            # machine tokens need a home dir to scope file ops to
            con.execute("ALTER TABLE api_tokens ADD COLUMN slot TEXT")
        if "is_admin" not in tcols:
            # admin machine token: full FS + all rights except users_manage
            con.execute("ALTER TABLE api_tokens ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        con.commit()


def prune_metrics(path: str | Path, keep_hours: int = 24) -> None:
    cutoff = int(time.time()) - keep_hours * 3600
    with closing(connect(path)) as con:
        con.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))
        con.commit()


def prune_sessions(path: str | Path) -> int:
    """Delete expired sessions; returns how many went.

    A session row outlives its cookie: nothing ever removed one that simply ran
    out of time, so the table grew for the lifetime of the install. It is also
    the table every authenticated request writes to (the sliding TTL update), so
    leaving it unbounded slows the hot path, not just backups.
    """
    with closing(connect(path)) as con:
        cur = con.execute("DELETE FROM sessions WHERE expires_at < ?",
                          (int(time.time()),))
        con.commit()
        return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0


def jload(s: str | None, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default
