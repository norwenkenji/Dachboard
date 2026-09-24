"""Dynamic slot provisioning: linux user + home + quota + ttyd + nginx gate
+ a stable port in the `slots` registry.

Slots are no longer pre-declared in config.yaml — an admin names one and it is
built on demand (Telegram bot, or any other caller with root).

Every step is argv-only (no shell) and idempotent, so a half-finished create
can simply be retried. Root-only: this writes /etc/systemd, /etc/nginx and
calls useradd.
"""
from __future__ import annotations

import re
import time
from contextlib import closing
from pathlib import Path

from . import quota as Q
from . import runner as R

# starts with a letter, then a-z 0-9 _ - ; no dots or '@' so the name can never
# be read as a systemd template instance (dach-ttyd-a@b.service) or a path.
SLOT_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,29}$")

NGINX_DIR = Path("/etc/nginx/dachboard")
UNIT_DIR = Path("/etc/systemd/system")

# A slot becomes a linux user running a writable shell. Handing out one of
# these names would hand out that account, so they are refused outright.
RESERVED = {
    "root", "zxc", "dachboard", "dach", "admin", "administrator", "user",
    "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
    "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
    "messagebus", "syslog", "uuidd", "tcpdump", "avahi", "usbmux", "dnsmasq",
    "rtkit", "whoopsie", "sssd", "kernoops", "saned", "pulse", "gdm", "hplip",
    "colord", "geoclue", "sshd", "postgres", "mysql", "mariadb", "redis",
    "mongodb", "docker", "podman", "nginx", "ttyd", "tmux", "git", "gitea",
    "ftp", "telnet", "operator", "shutdown", "halt", "reboot", "systemd",
}
RESERVED_PREFIX = ("dach-", "systemd-", "sys-", "dev-", "nginx", "ttyd-",
                   "gitea-", "git-", "docker-", "_apt", "ntp")


def ttyd_unit(slot: str, port: int) -> str:
    return f"""[Unit]
Description=Dachboard ttyd for {slot}
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User={slot}
WorkingDirectory=/home/{slot}
ExecStart=/usr/local/bin/ttyd -i 127.0.0.1 -p {port} --writable --index /opt/dachboard/term/index.html tmux -L dach-{slot} -f /opt/dachboard/term/tmux.conf new -A -s main bash -l
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""


def nginx_term_conf(slot: str, port: int) -> str:
    return f"""location = /dash-auth-{slot} {{
    internal;
    proxy_pass http://127.0.0.1:8420/api/auth-check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Cookie $http_cookie;
    proxy_set_header X-Target term;
    proxy_set_header X-Slot {slot};
    # audit records the real client, not the proxy's loopback address
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}}
location /term/{slot}/ {{
    auth_request /dash-auth-{slot};
    proxy_pass http://127.0.0.1:{port}/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_buffering off;
    proxy_cache off;
    tcp_nodelay on;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}}
"""


def unit_path(slot: str) -> Path:
    return UNIT_DIR / f"dach-ttyd-{slot}.service"


def nginx_path(slot: str) -> Path:
    return NGINX_DIR / f"term-{slot}.conf"


def name_error(slot: str, known: set[str] | None = None) -> str | None:
    """Why this slot name is unacceptable, or None when it is fine.
    `known` = slots we created ourselves (an existing linux user with that name
    is only acceptable when we own it)."""
    s = str(slot or "").strip()
    if not SLOT_NAME_RE.fullmatch(s):
        return ("bad name: a-z first, then a-z 0-9 _ - , 2..30 chars, "
                "no dots or @")
    low = s.lower()
    if low in RESERVED:
        return f"name {s!r} is reserved"
    if low.startswith(RESERVED_PREFIX):
        return f"name {s!r} uses a reserved prefix"
    if R.user_exists(low) and low not in (known or set()):
        # refusing is the whole point: provisioning "zxc" would hand out a
        # shell as that existing account
        return f"linux user {s!r} already exists and is not a dachboard slot"
    return None


def allocate_port(db: str, base: int = 7681, top: int = 7799) -> int:
    """Lowest free port in the registry window. `base-1` stays the root shell."""
    from . import db as D
    with closing(D.connect(db)) as con:
        used = {int(r["port"]) for r in con.execute("SELECT port FROM slots")}
    used.add(base - 1)                       # root ttyd
    for p in range(base, top + 1):
        if p not in used:
            return p
    raise ValueError("no free slot ports left")


def register_slot(db: str, slot: str, port: int) -> None:
    from . import db as D
    with closing(D.connect(db)) as con:
        con.execute("INSERT OR REPLACE INTO slots(slot,port,created_at)"
                    " VALUES(?,?,?)", (slot, port, int(time.time())))
        con.commit()


def registered_slots(db: str) -> list[str]:
    from . import db as D
    with closing(D.connect(db)) as con:
        return [r["slot"] for r in con.execute("SELECT slot FROM slots ORDER BY slot")]


def port_of(db: str, slot: str) -> int | None:
    from . import db as D
    with closing(D.connect(db)) as con:
        r = con.execute("SELECT port FROM slots WHERE slot=?", (slot,)).fetchone()
    return r["port"] if r else None


def create_slot(db: str, slot: str, disk_quota: str | None = None,
                base: int = 7681) -> dict:
    """Build a slot end to end. Returns {"ok", "port", "log": [...]}."""
    log: list[str] = []
    err = name_error(slot, set(registered_slots(db)))
    if err:
        return {"ok": False, "msg": err, "log": log}

    code, out = R.run_as(["id", "-u", slot], None, 20)
    if code != 0:
        code, out = R.run_as(["useradd", "-m", "-s", "/usr/sbin/nologin", slot],
                             None, 60)
        if code != 0:
            return {"ok": False, "msg": f"useradd failed: {out}", "log": log}
        log.append(f"linux user {slot} created")
        R.run_as(["chown", f"{slot}:{slot}", f"/home/{slot}"], None, 30)
        R.run_as(["chmod", "750", f"/home/{slot}"], None, 30)
    else:
        log.append(f"linux user {slot} reused")

    home = Path(f"/home/{slot}")
    if not home.is_dir():
        home.mkdir(parents=True, exist_ok=True)
        R.run_as(["chown", f"{slot}:{slot}", str(home)], None, 30)
        R.run_as(["chmod", "750", str(home)], None, 30)
        log.append("home dir created")

    if disk_quota:
        ok, msg = Q.apply_quota(slot, disk_quota, "/")
        log.append(f"quota {disk_quota}: {'ok' if ok else 'skip ' + msg}")

    port = port_of(db, slot) or allocate_port(db, base)
    unit_path(slot).write_text(ttyd_unit(slot, port))
    for argv in (["systemctl", "daemon-reload"],
                 ["systemctl", "enable", f"dach-ttyd-{slot}.service"],
                 ["systemctl", "restart", f"dach-ttyd-{slot}.service"]):
        code, out = R.run_as(argv, None, 60)
        if code != 0 and argv[1] != "enable":
            return {"ok": False, "msg": f"{' '.join(argv)} failed: {out}",
                    "log": log}
    log.append(f"ttyd {slot} on :{port}")

    NGINX_DIR.mkdir(parents=True, exist_ok=True)
    conf = nginx_path(slot)
    conf.write_text(nginx_term_conf(slot, port))
    code, out = R.run_as(["nginx", "-t"], None, 30)
    if code != 0:
        conf.unlink(missing_ok=True)
        return {"ok": False, "msg": f"nginx -t failed, conf removed: {out}",
                "log": log}
    R.run_as(["systemctl", "reload", "nginx"], None, 30)
    log.append("nginx term gate installed")

    register_slot(db, slot, port)
    log.append(f"registered slot {slot} -> port {port}")
    return {"ok": True, "msg": "; ".join(log), "port": port, "log": log}


def remove_slot(db: str, slot: str, wipe: bool = False) -> dict:
    """Tear a slot's shell down. `wipe` also deletes the linux user, its home
    and the registry entry; without it the data and the reserved port stay, so
    the same slot name can be handed out again later."""
    from . import db as D
    log: list[str] = []
    if slot not in registered_slots(db):
        err = name_error(slot, set())
        if err:
            return {"ok": False, "msg": err, "log": log}
    for argv in (["systemctl", "stop", f"dach-ttyd-{slot}.service"],
                 ["systemctl", "disable", f"dach-ttyd-{slot}.service"]):
        R.run_as(argv, None, 60)
    unit_path(slot).unlink(missing_ok=True)
    R.run_as(["systemctl", "daemon-reload"], None, 30)
    log.append(f"ttyd {slot} removed")

    conf = nginx_path(slot)
    if conf.exists():
        conf.unlink()
        code, out = R.run_as(["nginx", "-t"], None, 30)
        if code == 0:
            R.run_as(["systemctl", "reload", "nginx"], None, 30)
            log.append("nginx term gate removed")
        else:
            log.append(f"nginx -t failed after removal: {out}")

    if not wipe:
        log.append(f"slot {slot} data kept (registry entry stays, port reserved)")
        return {"ok": True, "msg": "; ".join(log), "log": log}

    with closing(D.connect(db)) as con:
        con.execute("DELETE FROM slots WHERE slot=?", (slot,))
        con.commit()
    log.append("registry entry dropped")
    if R.user_exists(slot):
        code, out = R.run_as(["userdel", "-r", slot], None, 60)
        log.append(f"linux user {slot} removed with home" if code == 0
                   else f"userdel failed: {out}")
    return {"ok": True, "msg": "; ".join(log), "log": log}
