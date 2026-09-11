import sqlite3

import pytest

from app import db as D


@pytest.fixture()
def path(tmp_path):
    p = tmp_path / "t.sqlite3"
    D.init(p)
    return p


def test_schema_tables(path):
    con = sqlite3.connect(path)
    tables = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "sessions", "commands", "runs", "metrics"} <= tables
    con.close()


def test_init_idempotent(path):
    D.init(path)
    D.init(path)


def test_prune_metrics(path):
    import time
    con = D.connect(path)
    old = int(time.time()) - 100_000
    con.execute("INSERT INTO metrics(ts,cpu) VALUES(?,?)", (old, 1.0))
    con.execute("INSERT INTO metrics(ts,cpu) VALUES(?,?)", (int(time.time()), 2.0))
    con.commit()
    con.close()
    D.prune_metrics(path, keep_hours=24)
    con = D.connect(path)
    rows = con.execute("SELECT cpu FROM metrics").fetchall()
    con.close()
    assert [r[0] for r in rows] == [2.0]


def test_jload():
    assert D.jload('{"a":1}', {}) == {"a": 1}
    assert D.jload("junk", {"d": 1}) == {"d": 1}
    assert D.jload(None, []) == []
