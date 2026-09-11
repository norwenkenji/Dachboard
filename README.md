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

Then expose it: see [TUNNEL.md](TUNNEL.md) for free tunnel options
(cloudflared quick/named, playit, ngrok, tailscale). The dashboard shows its
own public URL at `GET /api/tunnel` once a provider is wired in
`config.yaml`.

Next: create users in the UI (Users tab): login + temp password + slot
(`u-c1`…) + rights checkboxes + limits. The user sets their own password on
first login. Hand them the tunnel URL + credentials any way you like
(Telegram bot, QR, …) — that integration lives outside this repo.

## Layout

```
app/            FastAPI daemon (auth, rbac, metrics, runner, files, tunnel)
static/         vanilla-JS SPA, no build step
tunnel/         provider scripts (executable prints URL to stdout)
deploy/         install.sh, systemd units, nginx snippet
```

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
- Passwords: scrypt (stdlib). Sessions: random tokens, expiry, `HttpOnly` cookies.
- CSRF token on all mutating requests. Login rate-limit.
- Commands run **without shell** (`argv` arrays only), as the target Linux user
  via `runuser`, optionally inside a `systemd-run` slice with CPU/RAM caps.
- Terminals listen on loopback only; nginx gates them with `auth_request`
  against the dashboard session + `terminal` right + user match.
- Dashboard binds loopback. Put it behind your tunnel + login. That's the model.

## License

MIT.
