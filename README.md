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

## Quick start (server)

```bash
git clone https://github.com/norwenkenji/Dachboard.git /opt/dachboard
cd /opt/dachboard
sudo bash deploy/install.sh
sudo python3 /opt/dachboard/app/__main__.py create-admin
sudo systemctl enable --now dachboard.service
```

Copy `config.example.yaml` → `/opt/dachboard/config.yaml`, edit ports/paths,
`sudo systemctl restart dachboard.service`. Open `http://127.0.0.1:8420`
(or your tunnel URL + `/dash/` behind the nginx snippet in `deploy/nginx/`).

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

- Passwords: scrypt (stdlib). Sessions: random tokens, expiry, `HttpOnly` cookies.
- CSRF token on all mutating requests. Login rate-limit.
- Commands run **without shell** (`argv` arrays only), as the target Linux user
  via `runuser`, optionally inside a `systemd-run` slice with CPU/RAM caps.
- Terminals listen on loopback only; nginx gates them with `auth_request`
  against the dashboard session + `terminal` right + user match.
- Dashboard binds loopback. Put it behind your tunnel + login. That's the model.

## License

MIT.
