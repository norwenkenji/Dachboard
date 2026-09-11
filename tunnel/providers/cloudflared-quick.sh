#!/bin/sh
# Bundle provider: cloudflared quick-tunnel URL from a docker container's logs.
# Usage: cloudflared-quick.sh [container]
# Prints the fresh URL to stdout (dashboard scans for first http(s):// URL).
C="${1:-dachboard-tunnel}"
docker logs "$C" 2>&1 | grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com[^ "]*' | tail -1
