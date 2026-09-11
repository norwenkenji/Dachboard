#!/bin/bash
# Optional: expose the dashboard via a free cloudflared quick tunnel.
# Creates container "dachboard-tunnel" -> nginx 127.0.0.1:80 (/dash/, /term/).
# URL is ephemeral; dashboard picks it up via tunnel.providers.cloudflared-quick.
# Run as a user in the docker group. Idempotent.
set -euo pipefail
TARGET="${1:-http://127.0.0.1:80}"
NAME="${2:-dachboard-tunnel}"
command -v docker >/dev/null || { echo "need docker"; exit 1; }
if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  echo "container $NAME exists, (re)starting"
  docker start "$NAME" >/dev/null
else
  docker run -d --name "$NAME" --network host --restart always \
    cloudflare/cloudflared:latest --no-autoupdate tunnel --url "$TARGET"
fi
sleep 8
docker logs "$NAME" 2>&1 | grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com[^ "]*' | tail -1
