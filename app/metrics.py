"""Host metrics. stdlib + `docker` CLI. Best-effort, never raises."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from contextlib import suppress


def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def cpu_percent() -> float:
    try:
        def snap():
            parts = (_read("/proc/stat") or "").splitlines()[0].split()[1:]
            nums = [int(x) for x in parts]
            idle = nums[3] + nums[4]
            return sum(nums), idle
        t1, i1 = snap()
        time.sleep(0.2)
        t2, i2 = snap()
        dt, di = t2 - t1, i2 - i1
        return round((1 - di / dt) * 100, 1) if dt else 0.0
    except Exception:
        return 0.0


def mem() -> dict:
    out = {"total": 0, "used": 0, "free": 0}
    try:
        info = {}
        for line in (_read("/proc/meminfo") or "").splitlines():
            k, v = line.split(":", 1)
            info[k] = int(v.split()[0]) * 1024
        out = {"total": info.get("MemTotal", 0),
               "free": info.get("MemAvailable", info.get("MemFree", 0))}
        out["used"] = out["total"] - out["free"]
    except Exception:
        pass
    return out


def disk(path: str = "/") -> dict:
    try:
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        return {"total": total, "used": total - free, "free": free}
    except Exception:
        return {"total": 0, "used": 0, "free": 0}


def temps() -> dict:
    out = {}
    base = "/sys/class/thermal"
    try:
        for zone in sorted(os.listdir(base)):
            if not zone.startswith("thermal_zone"):
                continue
            t = _read(f"{base}/{zone}/type") or zone
            raw = _read(f"{base}/{zone}/temp")
            with suppress(ValueError, TypeError):
                out[t] = int(raw) / 1000.0 if raw and int(raw) > 1000 else (float(raw) if raw else 0)
    except OSError:
        pass
    return out


def load() -> list:
    try:
        return list(os.getloadavg())
    except Exception:
        return [0.0, 0.0, 0.0]


def uptime() -> float:
    try:
        return float((_read("/proc/uptime") or "").split()[0])
    except (OSError, ValueError, IndexError, TypeError):
        # IndexError/TypeError: the file is missing, empty or unreadable. It was
        # AttributeError before, which never fires — a None has no .split, but
        # `or ""` made it an empty string whose [0] raises IndexError instead.
        return 0.0


_host_cache: dict | None = None


def host_info() -> dict:
    """Static hardware/OS facts: hostname, OS, kernel, arch, CPU model, cores.
    Cached — none of this changes at runtime."""
    global _host_cache
    if _host_cache is not None:
        return _host_cache
    info = {"hostname": "", "os": "", "kernel": "", "arch": "",
            "cpu_model": "", "cpu_cores": os.cpu_count() or 0}
    try:
        u = os.uname()
        info.update(hostname=u.nodename, kernel=u.release, arch=u.machine)
    except Exception:
        pass
    try:
        for line in (_read("/etc/os-release") or "").splitlines():
            if line.startswith("PRETTY_NAME="):
                info["os"] = line.split("=", 1)[1].strip().strip('"')
                break
    except Exception:
        pass
    try:
        cores = 0
        for line in (_read("/proc/cpuinfo") or "").splitlines():
            if line.startswith("model name") and not info["cpu_model"]:
                info["cpu_model"] = line.split(":", 1)[1].strip()
            elif line.startswith("processor"):
                cores += 1
        if cores:
            info["cpu_cores"] = cores
    except Exception:
        pass
    _host_cache = info
    return info


def _docker(args: list, timeout: int = 10) -> subprocess.CompletedProcess:
    if not shutil.which("docker"):
        raise FileNotFoundError("docker")
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=timeout)


def containers() -> list:
    try:
        r = _docker(["ps", "-a", "--format", "json"])
        rows = []
        for line in r.stdout.strip().splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows
    except Exception:
        return []


def container_logs(name: str, tail: int = 200) -> str:
    try:
        r = _docker(["logs", "--tail", str(tail), name], timeout=15)
        return (r.stdout + r.stderr)[-100_000:]
    except Exception as e:
        return f"error: {e}"


def container_action(name: str, action: str) -> tuple[int, str]:
    if action not in ("start", "stop", "restart"):
        return 1, "forbidden action"
    try:
        r = _docker([action, name], timeout=60)
        return r.returncode, (r.stdout + r.stderr)[-4000:]
    except Exception as e:
        return 1, f"error: {e}"


def snapshot() -> dict:
    m = mem()
    d = disk("/")
    return {
        "ts": int(time.time()),
        "cpu": cpu_percent(),
        "mem": m,
        "disk": d,
        "temps": temps(),
        "load": load(),
        "uptime": uptime(),
        "host": host_info(),
    }
