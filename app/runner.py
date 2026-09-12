"""Command runner. argv-arrays only, NO shell. Runs as target Linux user."""
from __future__ import annotations

import shutil
import subprocess

try:
    import pwd
except ImportError:  # Windows: no user db
    pwd = None

MAX_OUTPUT = 64 * 1024


def _run(cmd: list[str], timeout: int) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + r.stderr)[-MAX_OUTPUT:]
        return r.returncode, out
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"
    except Exception as e:
        return 1, f"error: {e}"


def user_exists(name: str) -> bool:
    if pwd is None:
        return False
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def run_as(argv: list[str], run_as: str | None = None,
           timeout: int = 60, use_slice: bool = False,
           slice_name: str | None = None,
           cpu_quota: str | None = None, mem_max: str | None = None) -> tuple[int, str]:
    """Run argv (no shell). Returns (exit_code, output capped)."""
    if not argv or not all(isinstance(a, str) for a in argv):
        return 1, "bad argv"
    cmd = list(argv)
    if use_slice and slice_name and shutil.which("systemd-run"):
        scope = ["systemd-run", "--quiet", "--pipe", "--wait",
                 f"--slice={slice_name}", "--scope"]
        if run_as:
            scope.append(f"--uid={run_as}")
        if cpu_quota:
            scope.append(f"-pCPUQuota={cpu_quota}")
        if mem_max:
            scope.append(f"-pMemoryMax={mem_max}")
        scope += ["--"] + cmd
        cmd = scope
    elif run_as and shutil.which("runuser"):
        cmd = ["runuser", "-u", run_as, "--"] + cmd
    return _run(cmd, timeout)


def exec_in(slot: str, argv: list[str], timeout: int = 60) -> tuple[int, str]:
    """Run argv inside the slot's container (no shell, no tty).
    Used when the slot has a container; otherwise callers fall back to run_as."""
    if not argv or not all(isinstance(a, str) for a in argv):
        return 1, "bad argv"
    from . import slots as S
    try:
        name = S.container_name(slot)
    except ValueError as e:
        return 1, str(e)
    return _run(["docker", "exec", name] + list(argv), timeout)
