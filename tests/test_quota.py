import pytest

from app import quota as Q


def test_parse_sizes():
    assert Q.parse_size("2G") == 2 * 1024**3
    assert Q.parse_size("500m") == 500 * 1024**2
    assert Q.parse_size("100K") == 100 * 1024
    assert Q.parse_size("1.5G") == int(1.5 * 1024**3)
    assert Q.parse_size("1024") == 1024
    assert Q.parse_size("2 GB") == 2 * 1024**3
    for bad in ("", "abc", "-5G", "10X", "G", None):
        with pytest.raises(ValueError):
            Q.parse_size(bad)


def test_quota_argv():
    argv = Q.quota_argv("u-c1", "2G")
    assert argv == ["setquota", "-u", "u-c1", "2097152", "2097152", "0", "0", "/"]
    assert Q.quota_argv("u-c2", "500M", "/home")[-1] == "/home"
    with pytest.raises(ValueError):
        Q.quota_argv("u-c1", "0")


def test_apply_no_limit():
    ok, msg = Q.apply_quota("u-c1", None)
    assert not ok and "no limit" in msg
    ok, msg = Q.apply_quota("u-c1", "junk!!")
    assert not ok
