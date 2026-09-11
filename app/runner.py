"""Command runner. argv-arrays only, NO shell. Runs as target Linux user."""
from __future__ import annotations

import pwd
import shutil
import subprocess

MAX_OUTPUT = 64 * 1024


def user_exists(name: str) -> bool:
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
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + r.stderr)[-MAX_OUTPUT:]
        return r.returncode, out
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"
    except Exception as e:
        return 1, f"error: {e}"
