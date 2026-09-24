"""P0: slot provisioning builders + dry-run. No system side effects."""
import pathlib
import re

import pytest

from app import slots as S


def test_valid_slot_ok():
    assert S.valid_slot("u-c1") == "u-c1"
    assert S.valid_slot(" U-Test ") == "u-test"


@pytest.mark.parametrize("bad", ["", "a b", "../x", "u_c1",
                                 "x" * 33, "-lead", "semi;colon"])
def test_valid_slot_rejects(bad):
    with pytest.raises(ValueError):
        S.valid_slot(bad)


def test_names():
    assert S.container_name("u-c1") == "dach-u-c1"
    assert S.volume_name("u-c1", "pgdata") == "dach-u-c1-pgdata"
    assert S.home_dir("u-c1") == "/home/u-c1"
    with pytest.raises(ValueError):
        S.volume_name("u-c1", "../evil")


def test_cpu_to_docker():
    assert S.cpu_to_docker("50%") == "0.5"
    assert S.cpu_to_docker("100%") == "1"
    assert S.cpu_to_docker("2") == "2"
    assert S.cpu_to_docker(None) is None
    with pytest.raises(ValueError):
        S.cpu_to_docker("lots")


def test_user_argv():
    assert S.useradd_argv("u-c1") == [
        "useradd", "-m", "-s", "/usr/sbin/nologin", "u-c1"]
    assert S.userdel_argv("u-c1") == ["userdel", "u-c1"]
    assert S.userdel_argv("u-c1", True) == ["userdel", "-r", "u-c1"]


def test_container_run_argv():
    argv = S.container_run_argv("u-c1", "img:1", cpu="50%", mem="1G")
    assert argv[:4] == ["docker", "run", "-d", "--name"]
    assert "--cpus" in argv and "0.5" in argv
    assert "--memory" in argv and "1G" in argv
    assert "-v" in argv
    assert argv[-3:] == ["img:1", "sleep", "infinity"]
    assert "sleep" in S.container_run_argv("u-c1")  # image default


def test_container_update_needs_something():
    with pytest.raises(ValueError):
        S.container_update_argv("u-c1")
    assert "--memory" in S.container_update_argv("u-c1", mem="2G")


def test_provision_plan_order_and_validation():
    plan = S.provision_plan("u-c9", cpu="50%", mem="1G", disk_quota="2G")
    descs = [s["desc"] for s in plan]
    assert descs[0].startswith("create linux user")
    assert any("quota" in d for d in descs)
    assert descs[-1].startswith("start container")
    assert all(isinstance(s["argv"], list) and s["argv"] for s in plan)
    with pytest.raises(ValueError):
        S.provision_plan("u-c9", disk_quota="bogus")


def test_remove_plan_wipe_vs_keep():
    keep = S.remove_plan("u-c1")
    wipe = S.remove_plan("u-c1", wipe_data=True)
    assert not any("volume" in s["desc"] for s in keep)
    assert keep[-1]["argv"] == ["userdel", "u-c1"]
    assert sum("volume" in s["desc"] for s in wipe) == 2
    assert wipe[-1]["argv"] == ["userdel", "-r", "u-c1"]


def test_apply_plan_dry_run_executes_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(S.R, "run_as",
                        lambda *a, **k: (calls.append(a), (0, ""))[1])
    plan = S.provision_plan("u-c9", disk_quota="1G")
    res = S.apply_plan(plan, dry_run=True)
    assert res["dry_run"] and res["ok"] and calls == []
    assert len(res["steps"]) == len(plan)


def test_apply_plan_stops_on_first_failure(monkeypatch):
    monkeypatch.setattr(S.R, "run_as", lambda *a, **k: (1, "nope"))
    res = S.apply_plan(S.provision_plan("u-c9"), dry_run=False)
    assert res["ok"] is False
    assert len(res["steps"]) == 1
    assert res["steps"][0]["code"] == 1


def test_container_limits_skip_without_container(monkeypatch):
    monkeypatch.setattr(S.R, "run_as", lambda *a, **k: (1, "no such object"))
    assert S.container_exists("u-c1") is False
    ok, msg = S.apply_container_limits("u-c1", cpu="50%", mem="1G")
    assert ok is False and "legacy" in msg


def test_container_limits_applied(monkeypatch):
    seen = []

    def fake(argv, *a, **k):
        seen.append(argv)
        return 0, "dach-u-c1"

    monkeypatch.setattr(S.R, "run_as", fake)
    ok, _msg = S.apply_container_limits("u-c1", mem="2G")
    assert ok is True
    assert seen[0][:2] == ["docker", "inspect"]
    assert "--memory" in seen[1]


def test_apply_limits_best_effort(monkeypatch):
    # no container on disk-quota-less box: both parts report, nothing raises
    monkeypatch.setattr(S.R, "run_as", lambda *a, **k: (1, "nope"))
    res = S.apply_limits("u-c1", cpu="50%", mem="1G", disk_quota="2G")
    assert set(res) == {"ok", "disk", "container"}
    assert res["container"]["applied"] is False


def test_run_mounts_shared_ro_and_pg_tree():
    argv = S.container_run_argv("u-c1", "img:1")
    assert "/opt/shared:/opt/shared:ro" in argv
    assert "dach-u-c1-pgdata:/var/lib/postgresql" in argv
    assert S.container_run_argv("u-c1", shared_dir=None).count("-v") == 2
    # podman-in-container requirements
    assert "seccomp=unconfined" in argv
    assert "/dev/fuse" in argv
    # P4 strict default: no external network inside slot containers
    assert "--network" in argv and "none" in argv


def test_reset_plan_keeps_data():
    plan = S.reset_plan("u-c1", cpu="50%", mem="1G")
    assert [s["argv"][1] for s in plan] == ["stop", "rm", "run"]
    assert plan[0].get("optional") and plan[1].get("optional")
    assert not plan[2].get("optional")
    run = plan[2]["argv"]
    assert "dach-u-c1" in run and "--cpus" in run and "--network" in run
    assert "none" in run


def test_reset_missing_container_still_ok(monkeypatch):
    # stop+rm fail (nothing there), run succeeds -> ok True, nothing raises
    def fake(argv, *a, **k):
        return (0, "up") if argv[1] == "run" else (1, "no such container")

    monkeypatch.setattr(S.R, "run_as", fake)
    res = S.apply_plan(S.reset_plan("u-c9"), dry_run=False)
    assert res["ok"] is True
    assert [s["code"] for s in res["steps"]] == [1, 1, 0]


def test_slot_podman_wrapper_guards():
    body = pathlib.Path(__file__).parent.parent.joinpath(
        "deploy", "slot-podman").read_text()
    assert "runuser -u " in body
    assert "--network none" in body
    assert "XDG_RUNTIME_DIR" in body
    assert "HOME=" in body
    assert re.compile(r"\^?\[a-z\]").search(body)  # slot name validation


def test_provision_with_postgres_adds_optional_step():
    plan = S.provision_plan("u-c9", with_postgres=True)
    assert plan[-1]["argv"][:3] == ["docker", "exec", "dach-u-c9"]
    assert plan[-1].get("optional") is True


def test_apply_plan_tolerates_optional_failure(monkeypatch):
    monkeypatch.setattr(S.R, "run_as", lambda *a, **k: (1, "pg missing"))
    res = S.apply_plan(S.provision_plan("u-c9", with_postgres=True),
                       dry_run=False)
    assert res["ok"] is False  # useradd failed -> hard stop still works
    assert len(res["steps"]) == 1


def test_postgres_status_parsing(monkeypatch):
    out = ("Ver Cluster Port Status Owner Data directory Log file\n"
           "14 main 5432 online postgres /var/lib/postgresql/14/main x\n")
    monkeypatch.setattr(S.R, "run_as", lambda *a, **k: (0, out))
    assert S.postgres_status("u-c1") == "online"
    monkeypatch.setattr(S.R, "run_as",
                        lambda *a, **k: (0, "14 main 5433 down postgres d l\n"))
    assert S.postgres_status("u-c1") == "down"
    monkeypatch.setattr(S.R, "run_as", lambda *a, **k: (0, "Ver Cluster\n"))
    assert S.postgres_status("u-c1") == "missing"
    monkeypatch.setattr(S.R, "run_as", lambda *a, **k: (1, "no such file"))
    assert S.postgres_status("u-c1") == "no-postgres"


def test_postgres_ensure_branches(monkeypatch):
    calls = []

    def fake(argv, *a, **k):
        calls.append(argv[-2:])
        if argv[-1] == "pg_lsclusters":
            return 0, "14 main 5432 online postgres d l\n"
        raise AssertionError("should not run anything else")

    monkeypatch.setattr(S.R, "run_as", fake)
    ok, msg = S.postgres_ensure("u-c1")
    assert (ok, msg) == (True, "already online")
    assert calls == [["dach-u-c1", "pg_lsclusters"]]


def test_postgres_ensure_creates_then_starts(monkeypatch):
    seq = iter([(0, "Ver Cluster\n"), (0, "Creating...\n"), (0, "started\n")])
    seen = []
    monkeypatch.setattr(
        S.R, "run_as",
        lambda argv, *a, **k: (seen.append(argv[3]), seq.__next__())[1])
    ok, _ = S.postgres_ensure("u-c1")
    assert ok is True
    assert seen == ["pg_lsclusters", "pg_createcluster", "pg_ctlcluster"]
