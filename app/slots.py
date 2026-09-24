"""Slot provisioning: linux user + docker container + volumes + quotas.

P0: pure argv builders (unit-tested) + ordered plans with dry-run.
Nothing here touches the system unless apply_plan() is called with
dry_run=False — and nothing calls it yet (slots_v2 flag, P1+).
"""
from __future__ import annotations

import re

from . import quota as Q
from . import runner as R

SLOT_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
IMAGE_DEFAULT = "dach-slot:latest"
SHARED_DIR = "/opt/shared"   # host dir with shared read-only assets (P3+)
PG_VERSION = "14"


def valid_slot(name: str) -> str:
    """Validate + normalize a slot name. Raises ValueError."""
    s = str(name or "").strip().lower()
    if not SLOT_RE.fullmatch(s) or len(s) > 32:
        raise ValueError(f"bad slot: {name!r} (a-z, 0-9, dash, max 32)")
    return s


def container_name(slot: str) -> str:
    return f"dach-{valid_slot(slot)}"


def volume_name(slot: str, kind: str) -> str:
    k = str(kind or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9-]{1,20}", k):
        raise ValueError(f"bad volume kind: {kind!r}")
    return f"dach-{valid_slot(slot)}-{k}"


def home_dir(slot: str) -> str:
    return f"/home/{valid_slot(slot)}"


def cpu_to_docker(cpu: str | None) -> str | None:
    """'50%' -> '0.5', '2' -> '2', None -> None. Raises ValueError."""
    if cpu is None:
        return None
    s = str(cpu).strip()
    if s.endswith("%"):
        num = s[:-1]
        try:
            return str(float(num) / 100).rstrip("0").rstrip(".") or "0"
        except ValueError:
            raise ValueError(f"bad cpu quota: {cpu!r}") from None
    try:
        float(s)
    except ValueError:
        raise ValueError(f"bad cpu quota: {cpu!r}") from None
    return s


def useradd_argv(slot: str) -> list[str]:
    return ["useradd", "-m", "-s", "/usr/sbin/nologin", valid_slot(slot)]


def userdel_argv(slot: str, wipe_home: bool = False) -> list[str]:
    argv = ["userdel"]
    if wipe_home:
        argv.append("-r")
    argv.append(valid_slot(slot))
    return argv


def home_perms_argv(slot: str) -> list[list[str]]:
    s = valid_slot(slot)
    return [["chown", f"{s}:{s}", home_dir(s)],
            ["chmod", "755", home_dir(s)]]


def volume_create_argv(name: str) -> list[str]:
    return ["docker", "volume", "create", name]


def volume_rm_argv(name: str) -> list[str]:
    return ["docker", "volume", "rm", name]


def container_rm_argv(slot: str) -> list[str]:
    return ["docker", "rm", "-f", container_name(slot)]


def container_run_argv(slot: str, image: str = IMAGE_DEFAULT,
                       cpu: str | None = None, mem: str | None = None,
                       network: str | None = "none",
                       shared_dir: str | None = SHARED_DIR) -> list[str]:
    """Create+start the slot container (long-lived, unprivileged).
    network defaults to 'none' (P4 strict: no external net inside slots;
    code and packages come from the image + /opt/shared)."""
    s = valid_slot(slot)
    img = str(image or "").strip() or IMAGE_DEFAULT
    argv = ["docker", "run", "-d", "--name", container_name(s),
            "--hostname", s, "--restart", "unless-stopped",
            # podman-in-container needs these (still no new host privs:
            # userns maps to unprivileged range, caps stay dropped).
            # Without them rootless podman fails with "cannot clone".
            "--security-opt", "seccomp=unconfined",
            "--device", "/dev/fuse"]
    cpus = cpu_to_docker(cpu)
    if cpus:
        argv += ["--cpus", cpus]
    if mem:
        argv += ["--memory", str(mem).strip()]
    if network:
        argv += ["--network", str(network).strip()]
    argv += ["-v", f"{home_dir(s)}:{home_dir(s)}",
             "-v", f"{volume_name(s, 'pgdata')}:/var/lib/postgresql"]
    if shared_dir:
        argv += ["-v", f"{shared_dir}:/opt/shared:ro"]
    argv += [img, "sleep", "infinity"]
    return argv


def container_update_argv(slot: str, cpu: str | None = None,
                          mem: str | None = None) -> list[str]:
    """Live limits on a running container (no restart)."""
    argv = ["docker", "update", container_name(slot)]
    cpus = cpu_to_docker(cpu)
    if cpus:
        argv += ["--cpus", cpus]
    if mem:
        argv += ["--memory", str(mem).strip()]
    if len(argv) == 3:
        raise ValueError("nothing to update: pass cpu and/or mem")
    return argv


def provision_plan(slot: str, image: str = IMAGE_DEFAULT,
                   cpu: str | None = None, mem: str | None = None,
                   disk_quota: str | None = None,
                   network: str | None = None,
                   with_postgres: bool = False) -> list[dict]:
    """Ordered steps to build a slot. Pure: no execution. Raises ValueError."""
    s = valid_slot(slot)
    if disk_quota:
        Q.parse_size(disk_quota)  # validate early, fail before touching anything
    # list[dict] not list[dict[str, ...]]: some steps carry an extra "optional"
    # flag, so a value type inferred from the first literal would reject them.
    steps: list[dict] = [{"desc": f"create linux user {s}",
                          "argv": useradd_argv(s)}]
    for argv in home_perms_argv(s):
        steps.append({"desc": f"own {home_dir(s)}", "argv": argv})
    for kind in ("pgdata", "work"):
        steps.append({"desc": f"create volume {volume_name(s, kind)}",
                      "argv": volume_create_argv(volume_name(s, kind))})
    if disk_quota:
        steps.append({"desc": f"disk quota {disk_quota} on {s}",
                      "argv": Q.quota_argv(s, disk_quota, "/")})
    steps.append({"desc": f"start container {container_name(s)}",
                  "argv": container_run_argv(s, image, cpu, mem, network)})
    if with_postgres:
        steps.append({"desc": f"start postgres in {container_name(s)}",
                      "argv": postgres_start_argv(s), "optional": True})
    return steps


def remove_plan(slot: str, wipe_data: bool = False) -> list[dict]:
    """Ordered steps to tear a slot down. Pure: no execution."""
    s = valid_slot(slot)
    steps: list[dict] = [{"desc": f"remove container {container_name(s)}",
                          "argv": container_rm_argv(s)}]
    if wipe_data:
        for kind in ("pgdata", "work"):
            steps.append({"desc": f"remove volume {volume_name(s, kind)}",
                          "argv": volume_rm_argv(volume_name(s, kind))})
    steps.append({"desc": f"delete linux user {s}"
                  + (" (wipe home)" if wipe_data else " (keep home)"),
                  "argv": userdel_argv(s, wipe_data)})
    return steps


def reset_plan(slot: str, image: str = IMAGE_DEFAULT,
               cpu: str | None = None, mem: str | None = None,
               network: str | None = "none") -> list[dict]:
    """Reset a slot's system to the image, keeping ALL user data
    (home, volumes, user, quota). Pure: no execution.
    NOTE: postgres inside must be re-ensured after reset (runtime call)."""
    s = valid_slot(slot)
    return [
        {"desc": f"stop container {container_name(s)}",
         "argv": ["docker", "stop", container_name(s)], "optional": True},
        {"desc": f"remove container {container_name(s)}",
         "argv": container_rm_argv(s), "optional": True},
        {"desc": f"start container {container_name(s)}",
         "argv": container_run_argv(s, image, cpu, mem, network)},
    ]


def apply_plan(plan: list[dict], dry_run: bool = False,
               timeout: int = 120) -> dict:
    """Execute a plan via runner (as root). dry_run only lists the steps."""
    if dry_run:
        return {"dry_run": True, "ok": True,
                "steps": [s["desc"] for s in plan]}
    results = []
    for s in plan:
        code, out = R.run_as(s["argv"], None, timeout=timeout)
        results.append({"desc": s["desc"], "code": code,
                        "output": out.strip()[-500:]})
        if code != 0 and not s.get("optional"):
            return {"dry_run": False, "ok": False, "steps": results}
    # results and plan are always the same length here: the loop either runs to
    # completion or returns early, so strict is a real invariant, not a guess.
    ok = all(r["code"] == 0 or s.get("optional")
             for r, s in zip(results, plan, strict=True))
    return {"dry_run": False, "ok": ok, "steps": results}


def container_exists(slot: str) -> bool:
    """True when the slot container exists (running or not)."""
    code, _ = R.run_as(["docker", "inspect", container_name(slot)],
                       None, timeout=15)
    return code == 0


def apply_container_limits(slot: str, cpu: str | None = None,
                           mem: str | None = None) -> tuple[bool, str]:
    """Live CPU/RAM on a running container (no restart).
    Skips cleanly for legacy slots without a container."""
    if not container_exists(slot):
        return False, "no container (legacy slot) — limits stored, apply on next run"
    try:
        argv = container_update_argv(slot, cpu, mem)
    except ValueError as e:
        return False, str(e)
    code, out = R.run_as(argv, None, timeout=30)
    return (code == 0), out.strip()[-500:] or f"exit {code}"


def apply_limits(slot: str, cpu: str | None = None,
                 mem: str | None = None,
                 disk_quota: str | None = None) -> dict:
    """Apply all limits right now. Best effort per part; legacy slots
    without a container get disk quota + stored CPU/RAM."""
    from . import quota as Q
    s = valid_slot(slot)
    disk_ok, disk_msg = Q.apply_quota(s, disk_quota, "/")
    cont_ok, cont_msg = apply_container_limits(s, cpu, mem)
    return {"ok": disk_ok or cont_ok,
            "disk": {"applied": disk_ok, "msg": disk_msg},
            "container": {"applied": cont_ok, "msg": cont_msg}}


def postgres_start_argv(slot: str, version: str = PG_VERSION) -> list[str]:
    s = valid_slot(slot)
    return ["docker", "exec", container_name(s),
            "pg_ctlcluster", str(version), "main", "start"]


def postgres_status(slot: str, version: str = PG_VERSION) -> str:
    """Cluster state: 'online', 'down', 'missing', or 'no-postgres'."""
    code, out = R.run_as(["docker", "exec", container_name(slot),
                          "pg_lsclusters"], None, timeout=15)
    if code != 0:
        return "no-postgres"
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].lower().startswith("ver"):
            continue
        if parts[0] == str(version) and parts[1] == "main":
            return "online" if parts[3] == "online" else "down"
    return "missing"


def postgres_ensure(slot: str, version: str = PG_VERSION,
                    timeout: int = 120) -> tuple[bool, str]:
    """Make sure the slot's postgres cluster exists and runs.
    Data lives on the slot's pgdata volume, survives rebuilds."""
    s = valid_slot(slot)
    name = container_name(s)
    st = postgres_status(s, version)
    if st == "online":
        return True, "already online"
    if st == "no-postgres":
        return False, "no postgres in image"
    if st == "missing":
        code, out = R.run_as(["docker", "exec", name, "pg_createcluster",
                              str(version), "main"], None, timeout=timeout)
        if code != 0:
            return False, out.strip()[-500:] or f"exit {code}"
    code, out = R.run_as(["docker", "exec", name, "pg_ctlcluster",
                          str(version), "main", "start"], None,
                         timeout=timeout)
    return (code == 0), out.strip()[-500:] or f"exit {code}"
