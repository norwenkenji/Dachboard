import importlib.util
import re

import pytest

SPEC = importlib.util.spec_from_file_location(
    "tunnel_setup", "deploy/tunnel-setup.py")
ts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ts)


def test_zone_of():
    assert ts.zone_of("dash.example.com", None) == "example.com"
    assert ts.zone_of("dash.example.com", "other.zone") == "other.zone"
    with pytest.raises(SystemExit):
        ts.zone_of("localhost", None)


def test_cname_payload():
    p = ts.cname_payload("dash.example.com", "abc.cfargotunnel.com")
    assert p == {"type": "CNAME", "name": "dash.example.com",
                 "content": "abc.cfargotunnel.com", "proxied": True, "ttl": 1}


def test_ngrok_pattern():
    sample = '{"tunnels":[{"public_url":"https://abcd-1-2-3.ngrok-free.app","proto":"https"}]}'
    m = re.search(r'https://[a-z0-9.-]+\.ngrok[^"]*', sample)
    assert m.group(0) == "https://abcd-1-2-3.ngrok-free.app"


def test_term_client_template():
    import pathlib
    tpl = pathlib.Path("term/client.template.html").read_text()
    for ph in ("__XTERM_CSS__", "__XTERM_JS__", "__FIT_JS__"):
        assert ph in tpl
    for token in ('"tty"', "AuthToken", "columns", "rows", "xterm-viewport"):
        assert token in tpl


def test_quick_pattern():
    sample = "2026/01/01 INF + https://gmbh-forests-golden-gods.trycloudflare.com"
    m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com[^ \"']*", sample)
    assert m.group(0) == "https://gmbh-forests-golden-gods.trycloudflare.com"
