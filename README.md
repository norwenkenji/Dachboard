# Dachboard

Self-hosted homelab panel for your own server. One daemon, one tunnel, per-user rights.

- **Overview** — CPU / RAM / disk / temps / load, service + container status
- **Containers** — `docker ps`, log streaming, start/stop/restart (per-right)
- **Terminal** — per-user [ttyd](https://github.com/tsl0922/ttyd) sessions behind nginx auth
- **Files** — file manager scoped to the user's home
- **Commands** — preset commands + constructor (argv-based, no shell), per-user allow-list
- **Users** — local accounts, granular rights matrix, per-user CPU/RAM/disk limits
- **Tunnel** — generic provider interface: dashboard exposes the *current public
  tunnel URL* on request (`GET /api/tunnel`). You wire your own provider
  (cloudflared quick/named, playit, ngrok, …). No vendor lock-in, no bot coupling.

Binds to `127.0.0.1` only. Expose it via your own tunnel (Cloudflare, playit, …)
and/or nginx. Never expose the port directly.

## Quick start (server, Ubuntu/Debian, root, python 3.10+)

```bash
git clone https://github.com/norwenkenji/Dachboard.git /root/dachboard-src
cd /root/dachboard-src
sudo bash deploy/install.sh
sudo systemctl start dachboard.service
# one-time setup token (burns after use):
sudo journalctl -u dachboard -n 5 | grep "SETUP TOKEN"
# open http://127.0.0.1:8420 → first-setup card → create admin
```

Then expose it: see [docs/TUNNEL.md](docs/TUNNEL.md) for free tunnel options
(cloudflared quick/named, playit, ngrok, tailscale). The dashboard shows its
own public URL at `GET /api/tunnel` once a provider is wired in
`config.yaml`.

## Docs

- [docs/TUNNEL.md](docs/TUNNEL.md) · [docs/TUNNEL.ru.md](docs/TUNNEL.ru.md) — tunnels
- [docs/PROVIDERS.md](docs/PROVIDERS.md) · [docs/PROVIDERS.ru.md](docs/PROVIDERS.ru.md) — tunnel providers
- [docs/SLOTS.md](docs/SLOTS.md) · [docs/SLOTS.ru.md](docs/SLOTS.ru.md) — what a slot actually is (read before granting one)
- [docs/MCP.md](docs/MCP.md) — let an LLM operate the server through the panel
- [docs/README.ru.md](docs/README.ru.md) — русская документация

Next: create users in the UI (Users tab): login + temp password + slot name +
rights checkboxes + limits. Slot names are free — type any new name
(`motya`, `itsmax`, …) and the panel builds the slot for you: linux user, home,
quota, ttyd unit, nginx auth gate, and a stable port recorded in the `slots`
table. The user sets their own password on first login. Hand them the tunnel
URL + credentials any way you like (Telegram bot, QR, …) — that integration
lives outside this repo.

## Upgrade

Re-run the installer — it preserves `config.yaml`, the database and
`.secret`, refreshes code/venv/units, then restart the service:

```bash
cd /root/dachboard-src && git pull && sudo bash deploy/install.sh
sudo systemctl restart dachboard.service
```

## Troubleshooting

- `install.sh` needs root, Debian/Ubuntu, python ≥ 3.10. Docker optional
  (containers page stays empty without it).
- Non-ext4 `/` → hard quotas skipped with a warning; usage-vs-limit still shown.
- Port `127.0.0.1:80` taken by another vhost → change `listen` in
  `deploy/nginx/dachboard.conf` (and the tunnel target) before installing.
- No GitHub access for ttyd download → install the `ttyd` binary manually to
  `/usr/local/bin/ttyd` and re-run the installer.
- Lost admin access: delete the admin row from SQLite and restart — a fresh
  one-time setup token appears in the journal (requires server shell).

## Layout

```
app/            FastAPI daemon (auth, rbac, metrics, runner, files, tunnel)
                + security.py (response headers, file delivery)
                + safepath.py (race-free anchored path walk)
                + audit.py (security event trail)
                + fileserv.py (streams from an open descriptor)
                + assets.py (content-hash asset versions)
static/         vanilla-JS SPA, no build step
tunnel/         provider scripts (executable prints URL to stdout)
deploy/         install.sh, systemd units, nginx snippet
docs/           documentation (EN + RU)
tests/          pytest, 350+ tests
```

Dependencies: `requirements.txt` is runtime only — that is what
`deploy/install.sh` installs. `requirements-dev.txt` adds pytest/httpx/ruff/
mypy and is what CI uses, so a production venv never carries test tooling.

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest -q          # TestClient-based, no server process
python -m ruff check .       # lint
python -m mypy               # type check
```

`tests/smoke_server.py` is a separate, manual end-to-end check: it boots a real
`python -m app.main serve` on a free port and walks the whole security chain
over actual HTTP — setup-token burn, login, uploading `evil.html` and proving
it downloads inert and is refused for inline preview, a non-admin getting 403
on `systemctl stop sshd.service`, the audit trail on disk (with no password in
it), and the login throttle returning 429. Run it before deploying and after
touching headers, auth or file delivery:

```bash
python tests/smoke_server.py
```

It is deliberately not collected by pytest (it spawns a process and binds a
port) and exits non-zero, listing every failed check.

## Tunnel providers

`config.yaml → tunnel.provider` is any executable. Its stdout is scanned for the
first `https?://…` URL. Bundled:

- `tunnel/providers/cloudflared-quick.sh [container]` — parses
  `docker logs <container>` for a `*.trycloudflare.com` URL (quick tunnels)
- `tunnel/providers/static.sh` — reads URL from a file (for named tunnels / manual)

`GET /api/tunnel` runs the provider (30s cache),
`POST /api/tunnel/refresh` drops the cache (right: `tunnel_view`).
Your own Telegram/Discord bot can poll this endpoint with an API token and hand
the fresh URL + per-user credentials to your people — same pattern as any
access-granter bot, but the bot lives outside this repo.

## Security model

- No default credentials, nothing secret in the repo or `.env`.
- **Bootstrap**: on first start with no admin present, the daemon generates a
  one-time setup token (file `0600` in the data dir, also logged to journal).
  `POST /api/setup` with that token creates the first admin and **burns** the
  token. Afterwards the endpoint 404s. Anyone with only dashboard or limited
  server access can't mint an admin.
- **Pre-register**: admin creates a user with a temp password + `must_change`
  flag. First login is rejected until the user sets their own password via
  `POST /api/first-password`. Temp password dies after that.
- Passwords: scrypt (stdlib). Sessions: random tokens, expiry, `HttpOnly`
  cookies with `SameSite=Lax`. Expired rows are garbage-collected hourly.
- CSRF token on all mutating requests; a rejected check is audited.
- Login rate-limit **per client address**, resolved from `X-Forwarded-For`
  (`forwarded_hops` in `config.yaml` tells the app how many proxies sit in
  front). Buckets expire and the table is bounded, so it neither locks out
  everyone nor grows forever.
- **HTTP hardening** on every response (`app/security.py`): strict CSP,
  `X-Content-Type-Options: nosniff`, `frame-ancestors 'none'` +
  `X-Frame-Options: DENY`, `Referrer-Policy`, HSTS, `no-store` everywhere
  except versioned static assets. The middleware fills headers with
  `setdefault`, so the two file-delivery endpoints deliberately override
  framing (see below) instead of inheriting `DENY`.
- **User-uploaded files are never served as documents.** `GET /api/files/download`
  forces `application/octet-stream` + `Content-Disposition: attachment`, so a
  stored `evil.html` cannot execute on the panel's origin — where it could read
  `/api/csrf` and mint an admin token. `GET /api/files/preview` renders inline
  only a fixed allow-list of passive media types (HTML/SVG/JS are refused with
  415). Preview is the one place framing is relaxed to `SAMEORIGIN` with
  `frame-ancestors 'self'` — the SPA embeds it in an `<iframe>`, so `DENY`
  would break it, while a wildcard would let any site frame user bytes on this
  origin. PDFs get `object-src 'self'` and no `sandbox`: Chrome's PDF plugin
  refuses to run in a unique origin. Bytes are streamed from the descriptor the
  safe walk opened, never re-opened by name.
- **Filesystem access is race-free by construction** (`app/safepath.py`): every
  path is walked from an anchored directory descriptor with `O_NOFOLLOW` at
  each hop, and symlink targets are re-walked rather than followed, so a slot
  user cannot swap a component for a symlink and make root touch a file outside
  their home. Absolute paths, `..`, and zip members that escape or are symlinks
  are rejected.
- **`systemctl` is admin-only.** `services_view` / `services_control` are in
  `rbac.ADMIN_ONLY`: the daemon runs unit control and `journalctl` as root, so
  they are not delegable. `containers_view` / `containers_control` remain
  grantable and scope to docker only.
- Commands run **without shell** (`argv` arrays only), as the target Linux user
  via `runuser`, optionally inside a `systemd-run` slice with CPU/RAM caps.
- Terminals listen on loopback only; nginx gates them with `auth_request`
  against the dashboard session + `terminal` right + user match.
- **Audit trail** on the `dachboard.audit` logger (`app/audit.py`): logins and
  failures, authorization and CSRF denials, user/slot/token CRUD, `systemctl`
  and docker actions, journal reads, preset command runs, irreversible file
  deletes and admin cross-slot access. Journal by default, plus a file if
  `audit.file` is set. Passwords, tokens, file contents and command output are
  never logged.
- Dashboard binds loopback. Put it behind your tunnel + login. That's the model.

### Slots are user accounts, not sandboxes

A slot is a plain Linux user with a home directory and a `tmux`/ttyd gateway
run as that user. There is **no container**, no network namespace and no
outbound-network restriction. See [docs/SLOTS.md](docs/SLOTS.md) for exactly
what is and is not enforced — and read it before handing a slot to anyone you
do not trust.

## License

MIT — see [LICENSE](LICENSE).
