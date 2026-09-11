"""Host metrics. stdlib + `docker` CLI. Best-effort, never raises."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time


def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def cpu_percent() -> float:
    try:
        def snap():
            parts = _read("/proc/stat").splitlines()[0].split()[1:]
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
        for line in _read("/proc/meminfo").splitlines():
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
    except OSError:
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
            try:
                out[t] = int(raw) / 1000.0 if raw and int(raw) > 1000 else (float(raw) if raw else 0)
            except (ValueError, TypeError):
                pass
    except OSError:
        pass
    return out


def load() -> list:
    try:
        return list(os.getloadavg())
    except OSError:
        return [0.0, 0.0, 0.0]


def uptime() -> float:
    try:
        return float(_read("/proc/uptime").split()[0])
    except (OSError, ValueError, AttributeError):
        return 0.0


def _docker(args: list, timeout: int = 10) -> subprocess.CompletedProcess:
    if not shutil.which("docker"):
        raise FileNotFoundError("docker")
    return subprocess.run(["docker"] + args, capture_output=True, text=True, timeout=timeout)


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
    }
