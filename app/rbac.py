"""RBAC: granular per-user rights. Admin bypasses everything."""
from __future__ import annotations

RIGHTS = [
    "overview",            # dashboard + metrics
    "containers_view",     # list containers + read container logs
    "containers_control",  # start/stop/restart a container
    "services_view",       # list systemd units + read the host journal
    "services_control",    # systemctl start/stop/restart a host unit
    "files",               # own file manager
    "terminal",            # own ttyd session
    "commands_run",        # run allowed preset commands
    "commands_edit",       # constructor: create/edit commands
    "tunnel_view",         # see public tunnel URL
    "users_manage",        # admin panel (implies all)
]

# services_* is host-wide systemd control and the daemon runs it as root, so a
# unit name is the only thing standing between a checkbox and `systemctl stop
# sshd` — or `journalctl -u dachboard`, which carries the one-time setup token
# and whatever secrets applications log. There is no meaningful allow-list of
# units for a general-purpose panel, so these stay admin-only. containers_* is
# the delegable subset: docker scopes it to containers, not to the host.
ADMIN_ONLY = {"users_manage", "commands_edit", "services_view",
              "services_control"}
# Machine tokens may hold these even though they are admin-only for humans:
# a token is minted by an admin and carries that admin's intent, but it must
# never mint users or other tokens (users_manage stays human-admin only).
TOKEN_HOLDABLE = {"commands_edit"}


def default_rights(is_admin: bool = False) -> dict:
    if is_admin:
        return dict.fromkeys(RIGHTS, True)
    return dict.fromkeys(RIGHTS, False) | {"overview": True}


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
