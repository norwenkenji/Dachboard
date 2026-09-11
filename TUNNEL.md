# TUNNEL.md — putting dachboard on the internet for free

The dashboard binds `127.0.0.1` only. To show it to your people you need a
tunnel. Any provider works: point `tunnel.provider` in `config.yaml` at a
script that prints the public URL, and the dashboard serves it at
`GET /api/tunnel` (cached, plus a fallback file for external bots).

## Option A: cloudflared quick tunnel (easiest, no account, URL changes)

```bash
bash deploy/tunnel-cloudflared.sh   # -> https://xxx.trycloudflare.com
```

Default config already reads that container's logs
(`tunnel/providers/cloudflared-quick.sh dachboard-tunnel`).
Downside: URL changes on every container recreate — re-share the link.
Your access-granter bot can poll `GET /api/tunnel` and forward the fresh URL.

## Option B: cloudflared named tunnel (stable subdomain, free account)

1. `cloudflared tunnel login`, `cloudflared tunnel create dachboard`
2. Route a hostname to it (needs a domain on Cloudflare, free tier ok)
3. Point the tunnel at `http://127.0.0.1:80` (nginx: `/dash/`, `/term/`)
4. Provider: `tunnel/providers/static.sh /opt/dachboard/data/my-url.txt`
   (write your stable URL into that file once)

## Option C: playit / ngrok / tailscale funnel

Run their agent pointing at `127.0.0.1:80`, then either:

- `static.sh` with your stable URL in a file, or
- write your own 5-line provider (see `tunnel/README.md`) that queries the
  agent's local API and prints the URL.

## Notes

- HTTPS is terminated by the tunnel provider. Keep `cookie_secure: true`.
- Never publish the raw port. The threat model assumes loopback-only.
- Quick-tunnel URLs are public-by-obscurity: the login wall is the real gate.
  Use 12+ char passwords (setup enforces it for admin).
