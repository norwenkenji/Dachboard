import sys

from app import tunnel as T


def provider():
    return [sys.executable, "-c", "print('go to https://abc-123.trycloudflare.com now')"]


def setup_function(_):
    T.refresh()


def test_extracts_url():
    url = T.current(provider()[0], provider()[1:], cache_seconds=0)
    assert url == "https://abc-123.trycloudflare.com"


def test_no_url_none():
    url = T.current(sys.executable, ["-c", "print('nothing here')"], cache_seconds=0)
    assert url is None


def test_cache_and_refresh():
    T.refresh()
    u1 = T.current(provider()[0], provider()[1:], cache_seconds=60)
    assert u1 is not None
    # provider now broken, cache must still answer
    u2 = T.current("definitely-missing-binary-xyz", [], cache_seconds=60)
    assert u2 == u1
    T.refresh()
    u3 = T.current("definitely-missing-binary-xyz", [], cache_seconds=60)
    assert u3 is None


def test_cache_file_fallback(tmp_path):
    T.refresh()
    f = tmp_path / "url.txt"
    f.write_text("https://saved.example.com/x")
    url = T.current("definitely-missing-binary-xyz", [], cache_seconds=0,
                    cache_file=str(f))
    assert url == "https://saved.example.com/x"


def test_trailing_punct_stripped():
    url = T._run_provider(sys.executable,
                          ["-c", "print('(see https://a.example.com).')"])
    assert url == "https://a.example.com"
