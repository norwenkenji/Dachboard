# Slots: what a slot actually is

> **Read this before granting anyone a slot.** An earlier revision of this file
> described a container-per-slot design that the code does not implement. What
> follows matches `app/provision.py` as it stands. If you need container-grade
> isolation, see [Slots v2](#slots-v2-not-implemented) — it is not finished.

A slot is a **plain Linux user with a home directory**, nothing more. There is
no container, no private network namespace and no chroot. The isolation you get
is exactly the standard Unix permission model: you are `uid=<slot>`, you own
`/home/<slot>`, and you cannot read or write anything you do not own.

## Names and ports

Slots are **created on demand** — there is no pre-declared list. Name one in
the Users tab (or through the Telegram bot) and the panel builds it: linux user,
home, quota, ttyd unit, nginx auth gate. Its port is the lowest free one in
`port_base..port_base+118` (`port_base-1` stays the root shell) and is recorded
in the `slots` table, so it survives restarts and reordering.

A name is refused if it is reserved (`root`, service names, `dach-*` …) or if a
Linux user with that name already exists and is not a dachboard slot —
provisioning it would hand out a shell as that account. Shape:
`^[a-z][a-z0-9_-]{1,29}$` — no dots or `@`, so a name can never be parsed as a
systemd template instance or a path component.

## Shell

The Shell tab opens a `tmux` session inside a ttyd gateway that systemd runs as
`User=<slot>` (`deploy/systemd/dach-ttyd-slot.service.template`). **You are the
slot user, not root.** You can do anything inside your own home; elsewhere you
have the rights of an unprivileged account — which is to say, read access to
whatever is world-readable on the host.

That last part is the honest caveat: `/etc/passwd`, `/proc`, world-readable
files under `/opt`, and the host's world-readable directories are visible. A
slot is a *user account*, not a sandbox. Do not put a hostile or untrusted
person in one and assume they are cut off from the machine.

## Limits (editable anytime, in the user's row)

- **Disk** — a real hard cap, enforced by ext4 `usrquota` via `setquota`
  (`app/quota.py`). Requires `/` to be ext4 with `usrquota`; `install.sh` adds
  the mount option and runs `quotaon`. On another filesystem the field is
  accepted but cannot be enforced, and the panel reports it as skipped.
- **CPU / RAM** — enforced **only on preset command runs**, and only when
  `systemd-run` is available: those get wrapped in a transient scope under
  `dach-<slot>.slice` with `-pCPUQuota=` / `-pMemoryMax=` (`app/runner.py`).
  **The interactive shell is not limited.** A ttyd session does not go through
  `run_as`, so a runaway loop in the Shell tab is capped by nothing but the
  host. Do not read these two fields as "this user can never use more".

## What is *not* there

Everything below appears in `app/slots.py` and in the `slot-image` Dockerfile,
but nothing in the running panel reaches it:

- **no container** — `provision.create_slot()` never calls `docker run`.
- **no postgres** per slot.
- **no `/opt/shared`** — the directory is not created and not mounted.
- **no rootless podman**, no `slot-podman` preset.
- **no outbound-network restriction.** There is no `ipset`/`nftables` rule and
  no network namespace. A slot with shell access has the host's network
  connectivity and can reach the internet.

`app/slots.py` is only reachable from `runner.exec_in()`, which runs when
`container_exists(slot)` is true — and since no container is ever created, that
branch does not execute. The code is kept for the planned design below.

## Slots v2 (not implemented)

`config.example.yaml` carries `slots_v2`, `slot_image` and `slot_network`, and
`deploy/systemd/dach-ttyd-slotv2.service.template` plus `deploy/slot-image/`
exist to support them. **No module in `app/` reads those three keys.** Turning
them on today does nothing.

Before enabling that path, review it deliberately: `container_run_argv()`
passes `--security-opt seccomp=unconfined` and `--device /dev/fuse`, and the
slot image installs docker and rootless podman inside. The comment there claims
"still no new host privs", which is optimistic — an unfiltered seccomp profile
plus `/dev/fuse` is a meaningfully larger kernel attack surface than a default
container. It may well be the right trade-off for what slots v2 is for, but it
should be a decision, not an inheritance.

## Panel-side guarantees that *are* real

The slot boundary is enforced by Unix permissions, and the panel additionally
refuses to cross it on the slot user's behalf:

- every file operation walks the path from an anchored directory descriptor
  with `O_NOFOLLOW` at each hop, so a symlink inside a home cannot redirect the
  daemon (which runs as root) to a file outside it — `app/safepath.py`;
- absolute paths and `..` are rejected outright, as are zip members that escape
  the destination or are symlinks;
- uploaded bytes are never served back as an active document: downloads are
  forced to `application/octet-stream` + `Content-Disposition: attachment`, and
  inline preview is limited to a fixed list of passive media types —
  `app/security.py`.

## Don'ts

- `apt install` inside a slot needs root and will fail — not because of a
  network policy, but because you are not root.
- Your files live in your home; that is also the only thing the disk quota
  measures.
- "Reset system to image" from an older version of this document does not
  exist. There is no image. Wiping a slot (`DELETE /api/slots/<slot>` with
  `wipe`) runs `userdel -r` and the home is gone for good — it is audited for
  exactly that reason.
