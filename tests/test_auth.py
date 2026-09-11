import time

from app import auth


def test_hash_roundtrip():
    h = auth.hash_password("correct-horse-8")
    assert auth.verify_password("correct-horse-8", h)
    assert not auth.verify_password("wrong", h)


def test_hash_unique_salts():
    assert auth.hash_password("same") != auth.hash_password("same")


def test_hash_malformed():
    assert not auth.verify_password("x", "garbage")
    assert not auth.verify_password("x", "")


def test_tokens_unique():
    toks = {auth.new_token() for _ in range(100)}
    assert len(toks) == 100


def test_now_sane():
    assert abs(auth.now() - time.time()) < 5
