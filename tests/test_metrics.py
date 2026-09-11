from app import metrics as M


def test_snapshot_keys():
    s = M.snapshot()
    assert set(s) >= {"ts", "cpu", "mem", "disk", "temps", "load", "uptime"}
    assert set(s["mem"]) >= {"total", "used", "free"}
    assert set(s["disk"]) >= {"total", "used", "free"}
    assert isinstance(s["load"], list) and len(s["load"]) == 3


def test_containers_no_crash():
    assert isinstance(M.containers(), list)


def test_container_action_forbidden():
    code, _ = M.container_action("x", "rm")
    assert code == 1


def test_logs_no_crash():
    assert isinstance(M.container_logs("no-such-container-xyz"), str)
