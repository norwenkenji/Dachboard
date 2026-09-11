#!/usr/bin/env python3
"""Automated tunnel setup for dachboard. No browser needed.

  quick                  zero creds, ephemeral URL (trycloudflare)
  named  --cf-token T --host dash.example.com
                         stable URL via Cloudflare API (needs API token with
                         Account/Tunnel:Edit + Zone/DNS:Edit on the zone)
  ngrok  --token T       stable-ish URL via ngrok (token from ngrok dashboard)

Examples:
  python3 deploy/tunnel-setup.py quick
  python3 deploy/tunnel-setup.py named --cf-token $CF_TOKEN --host dash.example.com
  python3 deploy/tunnel-setup.py ngrok --token $NGROK_TOKEN
  ... --dry-run   # print what would happen, change nothing
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request

CF_API = "https://api.cloudflare.com/client/v4"


def sh(*argv: str, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=capture, text=True, timeout=120)


def cf(method: str, path: str, token: str, payload: dict | None = None) -> dict:
    req = urllib.request.Request(
        CF_API + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = json.loads(r.read().decode())
    except Exception as e:
        raise SystemExit(f"cloudflare api error on {method} {path}: {e}")
    if not body.get("success"):
        raise SystemExit(f"cloudflare rejected {method} {path}: {body.get('errors')}")
    return body["result"]


def zone_of(host: str, override: str | None) -> str:
    if override:
        return override
    parts = host.split(".")
    if len(parts) < 2:
        raise SystemExit("need a dotted hostname")
    return ".".join(parts[-2:])


def find_zone_id(token: str, zone: str) -> tuple[str, str]:
    res = cf("GET", f"/zones?name={zone}", token)
    if not res:
        raise SystemExit(f"zone {zone} not found (token needs Zone:Read?)")
    return res[0]["id"], res[0]["account"]["id"]


def create_named_tunnel(token: str, account_id: str, name: str) -> tuple[str, str]:
    res = cf("POST", f"/accounts/{account_id}/cfd_tunnel", token, {"name": name})
    return res["id"], res["token"]


def cname_payload(host: str, target: str) -> dict:
    return {"type": "CNAME", "name": host, "content": target, "proxied": True, "ttl": 1}


def upsert_cname(token: str, zone_id: str, host: str, target: str) -> None:
    existing = cf("GET", f"/zones/{zone_id}/dns_records?name={host}&type=CNAME", token)
    payload = cname_payload(host, target)
    if existing:
        cf("PUT", f"/zones/{zone_id}/dns_records/{existing[0]['id']}", token, payload)
    else:
        cf("POST", f"/zones/{zone_id}/dns_records", token, payload)


def docker_run(name: str, args: list[str], dry: bool) -> None:
    if dry:
        print("would run: docker", " ".join(["run", "-d", "--name", name] + args))
        return
    has = sh("docker", "ps", "-a", "--format", "{{.Names}}", capture=True).stdout.split()
    if name in has:
        print(f"container {name} exists, starting")
        sh("docker", "start", name)
        return
    r = sh("docker", "run", "-d", "--name", name, "--network", "host",
           "--restart", "always", *args)
    if r.returncode != 0:
        raise SystemExit("docker run failed")


def quick_url(name: str, timeout: int = 60) -> str | None:
    import re
    end = time.time() + timeout
    while time.time() < end:
        r = sh("docker", "logs", name, capture=True)
        m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com[^ \"']*", r.stdout + r.stderr)
        if m:
            return m.group(0)
        time.sleep(3)
    return None


def cmd_quick(a) -> None:
    docker_run("dachboard-tunnel",
               ["cloudflare/cloudflared:latest", "--no-autoupdate",
                "tunnel", "--url", a.target], a.dry_run)
    if a.dry_run:
        return
    url = quick_url("dachboard-tunnel")
    print(url or "no URL yet — check: docker logs dachboard-tunnel")
    print("provider: tunnel/providers/cloudflared-quick.sh dachboard-tunnel (default)")


def cmd_named(a) -> None:
    zone = zone_of(a.host, a.zone)
    print(f"zone: {zone}")
    if a.dry_run:
        print(f"would: find zone, create tunnel {a.name}, CNAME {a.host}, run connector")
        return
    zone_id, account_id = find_zone_id(a.cf_token, zone)
    tid, ctoken = create_named_tunnel(a.cf_token, a.account_id or account_id, a.name)
    upsert_cname(a.cf_token, zone_id, a.host, f"{tid}.cfargotunnel.com")
    docker_run("dachboard-tunnel",
               ["cloudflare/cloudflared:latest", "--no-autoupdate",
                "tunnel", "--no-autoupdate", "run", "--token", ctoken], a.dry_run)
    print(f"stable URL: https://{a.host}")
    print("provider: tunnel/providers/static.sh /opt/dachboard/data/my-url.txt")
    print(f"(write https://{a.host} into that file)")


def cmd_ngrok(a) -> None:
    docker_run("dachboard-tunnel",
               ["ngrok/ngrok:latest", "http", a.target,
                f"--authtoken={a.token}"], a.dry_run)
    if a.dry_run:
        return
    print("provider: tunnel/providers/ngrok.sh  (reads local api :4040)")


def main() -> None:
    ap = argparse.ArgumentParser(prog="tunnel-setup")
    sub = ap.add_subparsers(dest="mode", required=True)
    q = sub.add_parser("quick")
    q.add_argument("--target", default="http://127.0.0.1:80")
    q.add_argument("--dry-run", action="store_true")
    n = sub.add_parser("named")
    n.add_argument("--cf-token", required=True)
    n.add_argument("--host", required=True)
    n.add_argument("--name", default="dachboard")
    n.add_argument("--zone", default=None)
    n.add_argument("--account", default=None)
    n.add_argument("--dry-run", action="store_true")
    g = sub.add_parser("ngrok")
    g.add_argument("--token", required=True)
    g.add_argument("--target", default="127.0.0.1:80")
    g.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    {"quick": cmd_quick, "named": cmd_named, "ngrok": cmd_ngrok}[a.mode](a)


if __name__ == "__main__":
    main()
