# TUNNEL.md — putting dachboard on the internet for free

The dashboard binds `127.0.0.1` only. To show it to your people you need a
tunnel. Any provider works: point `tunnel.provider` in `config.yaml` at a
script that prints the public URL, and the dashboard serves it at
`GET /api/tunnel` (cached, plus a fallback file for external bots).

## Option A: cloudflared quick tunnel (easiest, no account, URL changes)

```bash
python3 deploy/tunnel-setup.py quick
# -> https://xxx.trycloudflare.com
```

Default config already reads that container's logs
(`tunnel/providers/cloudflared-quick.sh dachboard-tunnel`).
Downside: URL changes on every container recreate — re-share the link.
Your access-granter bot can poll `GET /api/tunnel` and forward the fresh URL.
Fully automatic, zero credentials.

## Option B: cloudflared named tunnel (stable subdomain, free account)

Needs a Cloudflare API token (Account/Tunnel:Edit + Zone/DNS:Edit) and a
domain on Cloudflare. No browser — everything via API:

```bash
python3 deploy/tunnel-setup.py named --cf-token $CF_TOKEN --host dash.example.com
# -> stable URL: https://dash.example.com
```

This creates the tunnel, sets the DNS CNAME and runs the connector.
Then point the dashboard provider at the stable URL:

```yaml
tunnel:
  provider: tunnel/providers/static.sh
  args: [/opt/dachboard/data/my-url.txt]
```

```bash
echo https://dash.example.com > /opt/dachboard/data/my-url.txt
```

Note: `--host` zone defaults to the last two labels; pass `--zone` explicitly
for exotic TLDs (`--host a.dash.example.co.uk --zone example.co.uk`).

## Option C: ngrok (stable-ish URL, token from ngrok dashboard)

```bash
python3 deploy/tunnel-setup.py ngrok --token $NGROK_TOKEN
```

Provider: `tunnel/providers/ngrok.sh` (reads the agent's local `:4040` API).

## Option D: playit / tailscale funnel (manual claim)

These need a browser/click to claim the agent — can't be scripted. Run their
agent pointing at `127.0.0.1:80`, then use `static.sh` or write a 5-line
provider (see `tunnel/README.md`).

## Asking for the fresh tunnel from any code

No session needed — mint an API token in the UI (Users → api tokens,
scope `tunnel_view`; shown once, revocable, `last_used` tracked):

```bash
curl -H "Authorization: Bearer dach_..." https://<tunnel>/api/tunnel
# {"url": "https://xxx.trycloudflare.com"}
```

Any bot / site / script polls this and hands the fresh URL plus per-user
credentials to its people. Session cookies keep working too; Bearer calls
don't need CSRF (no cookies involved).

## Notes

- HTTPS is terminated by the tunnel provider. Keep `cookie_secure: true`.
- Never publish the raw port. The threat model assumes loopback-only.
- Quick-tunnel URLs are public-by-obscurity: the login wall is the real gate.
  Use 12+ char passwords (setup enforces it for admin).
