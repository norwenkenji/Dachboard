"""RBAC: granular per-user rights. Admin bypasses everything."""
from __future__ import annotations

RIGHTS = [
    "overview",            # dashboard + metrics
    "containers_view",     # list containers + read logs
    "containers_control",  # start/stop/restart
    "files",               # own file manager
    "terminal",            # own ttyd session
    "commands_run",        # run allowed preset commands
    "commands_edit",       # constructor: create/edit commands
    "tunnel_view",         # see public tunnel URL
    "users_manage",        # admin panel (implies all)
]

ADMIN_ONLY = {"users_manage", "commands_edit"}


def default_rights(is_admin: bool = False) -> dict:
    if is_admin:
        return {r: True for r in RIGHTS}
    return {r: False for r in RIGHTS} | {"overview": True}


def can(user: dict, right: str) -> bool:
    if user.get("is_admin"):
        return True
    rights = user.get("rights") or {}
    if right in ADMIN_ONLY:
        return False
    return bool(rights.get(right, False))
