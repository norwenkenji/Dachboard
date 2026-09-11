# Tunnel providers

`config.yaml → tunnel.provider` is any executable. The dashboard runs it,
takes the **first `http(s)://…` URL** on stdout, caches it
(`tunnel.cache_seconds`), and serves it at `GET /api/tunnel`.
Falls back to `tunnel.cache_file` when the provider prints nothing.

Bundled:

| script | use |
|---|---|
| `providers/cloudflared-quick.sh [container]` | `*.trycloudflare.com` URL from `docker logs` (ephemeral tunnels) |
| `providers/static.sh <file>` | URL kept in a file (named tunnels, manual) |

Write your own for playit / ngrok / tailscale funnel / plain file:

```sh
#!/bin/sh
# my-provider.sh — print exactly one URL
curl -s http://127.0.0.1:4040/api/tunnels | grep -Eo 'https://[^"]+'
```

Then point `tunnel.provider` at it. External bots (Telegram/Discord/…)
poll `GET /api/tunnel` with a logged-in session and hand the fresh URL plus
per-user credentials to their people. That integration lives outside this repo.
