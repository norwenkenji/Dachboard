#!/bin/bash
# Dachboard installer. Idempotent-ish. Run as root on the target server.
#   sudo bash deploy/install.sh
set -euo pipefail

DACH=/opt/dachboard
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PORT_BASE=7681

echo "== dachboard install =="

# --- packages ---
apt-get update -qq
apt-get install -y -qq python3 python3-venv nginx curl unzip quota 2>/dev/null || \
apt-get install -y -qq python3 python3-venv nginx curl unzip

# --- ttyd binary ---
if [ ! -x /usr/local/bin/ttyd ]; then
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) TTYD_ARCH=x86_64 ;; aarch64|arm64) TTYD_ARCH=aarch64 ;;
    *) echo "unknown arch $ARCH, install ttyd manually"; exit 1 ;;
  esac
  curl -sL "https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.${TTYD_ARCH}" \
    -o /usr/local/bin/ttyd
  chmod +x /usr/local/bin/ttyd
fi
ttyd --version || true

# --- tree ---
mkdir -p "$DACH" "$DACH/data"
cp -r "$REPO_DIR/app" "$REPO_DIR/static" "$REPO_DIR/tunnel" "$DACH/"
cp "$REPO_DIR/requirements.txt" "$DACH/"
[ -f "$DACH/config.yaml" ] || cp "$REPO_DIR/config.example.yaml" "$DACH/config.yaml"
chmod +x "$DACH"/tunnel/providers/*.sh

# --- venv ---
[ -d "$DACH/.venv" ] || python3 -m venv "$DACH/.venv"
"$DACH/.venv/bin/pip" install -q --upgrade pip
"$DACH/.venv/bin/pip" install -q -r "$DACH/requirements.txt"

# --- user slots ---
i=0
for slot in u-c1 u-c2 u-c3 u-c4; do
  if ! id "$slot" >/dev/null 2>&1; then
    useradd -m -s /usr/sbin/nologin "$slot"
    echo "created linux user $slot"
  fi
  port=$((PORT_BASE + i)); i=$((i + 1))
  # per-slot ttyd unit
  sed -e "s/%i/$slot/g" -e "s/PORT/$port/" \
    "$REPO_DIR/deploy/systemd/dach-ttyd-slot.service.template" \
    > "/etc/systemd/system/dach-ttyd-${slot}.service"
  systemctl enable "dach-ttyd-${slot}.service" >/dev/null
  # nginx per-slot term block
  mkdir -p /etc/nginx/dachboard
  cat > "/etc/nginx/dachboard/term-${slot}.conf" <<EOF
location /term/${slot}/ {
    auth_request /dash-auth?target=term&slot=${slot};
    proxy_pass http://127.0.0.1:${port}/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
}
EOF
done

# --- dashboard unit ---
cp "$REPO_DIR/deploy/systemd/dachboard.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable dachboard.service >/dev/null

# --- nginx ---
cp "$REPO_DIR/deploy/nginx/dachboard.conf" /etc/nginx/sites-available/dachboard
ln -sf /etc/nginx/sites-available/dachboard /etc/nginx/sites-enabled/dachboard
cat > /etc/nginx/dachboard/terms.conf <<'EOF'
include /etc/nginx/dachboard/term-*.conf;
EOF
nginx -t && systemctl reload nginx

echo "== done =="
echo "1. create admin:  cd /opt/dachboard && sudo .venv/bin/python -m app.main create-admin"
echo "2. edit /opt/dachboard/config.yaml (tunnel provider, ports)"
echo "3. start: sudo systemctl start dachboard.service"
echo "4. loopback check: curl http://127.0.0.1:8420/"
