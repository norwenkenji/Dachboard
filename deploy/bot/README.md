# Telegram bot: hand out dashboard access

The bot (`/home/zxc/gitea-bot/bot.py`, service `gitea-bot.service`) already gave
out Gitea accounts. Now it gives out **dashboard accounts too** — you grant
access, the user presses one button and gets a working account with a real
Linux slot built behind it.

The bot itself is **not in this repo** (it holds the Telegram token). This
folder holds the root-side helper it talks to.

## How you use it

Grant access (the account is *not* created yet, only promised):

```
+dash 7615838255
+dash 7615838255 motya                # pick the dashboard login
+dash 7615838255 motya zxcpsycho      # pick login and slot name
```

Login and slot are optional. The login defaults to the person's Telegram
username (or `tg<id>`); the slot defaults to a name derived from the login.
**Slot names are free** — no pre-declared list anywhere. The bot validates the
shape up front and refuses a name that is already handed out, so the same slot
is never promised twice.

The user then presses **🖥 Получить аккаунт** and gets the URL, login, password
(18 random chars) and slot. First login forces a password change.

Revoke:

```
-dash 7615838255          # delete account, stop its shell, keep its files
-dash 7615838255 wipe     # ...and delete the Linux user with its home dir
-slot itsmax              # wipe a slot left behind by a revoke without wipe
```

Without `wipe` the files survive (and the slot stays registered, so the port is
not reused); the revoke message tells you the exact `-slot` line to clean up
later.

Buttons are not equal: **🖥 Дашборд** appears only for someone who was actually
granted access, and **🖧 SSH** (`ssh zxc@192.168.0.100`) only for the two owner
IDs hardcoded in `SSH_ADMINS`. That list is separate from `ADMIN_IDS` on
purpose — growing the admin list must never expose the SSH line.

## What "create" actually does

`deploy/bot/dach-adduser.py` runs as the one-shot unit `dach-adduser.service`
(root) and delegates everything to `app/provision.py` — the same module the web
UI calls for `POST /api/slots` and for creating a user with a new slot name.
One code path, two entry points:

1. slot name validated (shape, reserved names, pre-existing Linux users);
2. `useradd -m -s /usr/sbin/nologin <slot>` + home ownership 750;
3. disk quota from `config.yaml → defaults.disk_quota` (2G) via `setquota`;
4. `dach-ttyd-<slot>.service` — the slot's shell on the lowest free port in
   `port_base..port_base+118` (`port_base-1` stays the root shell), recorded in
   the `slots` table so the port survives restarts and reordering;
5. `/etc/nginx/dachboard/term-<slot>.conf` — `auth_request` gate, `nginx -t`
   before reload, config removed again if the test fails;
6. the dashboard user row: scrypt hash, `must_change_pw=1`, limits from
   `defaults`, rights = everything **except** `users_manage` and
   `commands_edit`.

Revoke undoes all of it (DB row, sessions, tokens bound to the slot, ttyd unit,
nginx gate, optionally the Linux user, home and registry entry).

## Why a root unit instead of an API call

The database is root-owned and the bot runs as `zxc`, which cannot even open it
for reading (WAL needs write access to the directory). Rather than hand the bot
admin credentials or a powerful API token, the bot writes `req.json`, starts the
unit through the `systemctl` NOPASSWD rule it already has, and reads `res.json`.
The request file is written 0600 and deleted by the root side immediately, so a
plaintext password never lingers.

The bot can therefore only ever ask for:

- a slot whose name passes `app/provision.py` — reserved names (`root`, `zxc`,
  `dachboard`, service names, reserved prefixes) are refused, and **any Linux
  user that is not a dachboard slot is refused**, because provisioning it would
  hand out a shell as that account;
- an account that is **never admin** (rights are hardcoded server-side, the
  request body cannot widen them);
- login `^[a-z0-9][a-z0-9_-]{2,31}$` — the first character may not be a dash, or
  a tool taking the login on argv would read it as a flag;
- password ≥ 8 chars.

`config.yaml` still accepts a legacy `slots:` list; names there keep their
index-based port. New installs leave it empty.

## Verified

End-to-end on the server with arbitrary slot names (`zxcpsycho`, `itsmax`):
create → first-password change → login → rights are all except `users_manage` /
`commands_edit` → terminal gate 200 as the owner, 403 for another slot.
Guards: `zxc` and `root` refused as slot names, a dotted name refused, a slot
already assigned refused, a duplicate login refused. Revoke without wipe kept
the home and the registry entry, revoke with wipe removed user + home + unit +
nginx conf, and `-slot`/`wipe_slot` cleaned up what a revoke left behind.
`nginx` and `dachboard` healthy throughout; `/home` back to just `zxc`.
