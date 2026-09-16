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
# Machine tokens may hold these even though they are admin-only for humans:
# a token is minted by an admin and carries that admin's intent, but it must
# never mint users or other tokens (users_manage stays human-admin only).
TOKEN_HOLDABLE = {"commands_edit"}


def default_rights(is_admin: bool = False) -> dict:
    if is_admin:
        return {r: True for r in RIGHTS}
    return {r: False for r in RIGHTS} | {"overview": True}


def can(user: dict, right: str) -> bool:
    if user.get("is_admin"):
        # admin machine tokens: everything except user/token management,
        # which stays human-only so a leaked token cannot mint admins
        if right == "users_manage":
            return user.get("via") != "token"
        return True
    rights = user.get("rights") or {}
    if right in ADMIN_ONLY:
        return (user.get("via") == "token" and right in TOKEN_HOLDABLE
                and bool(rights.get(right, False)))
    return bool(rights.get(right, False))
