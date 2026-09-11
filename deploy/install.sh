#!/bin/bash
# Dachboard installer. Idempotent-ish. Run as root on the target server.
#   sudo bash deploy/install.sh
set -euo pipefail

DACH=/opt/dachboard
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PORT_BASE=7681

echo "== dachboard install =="

# --- preflight ---
[ "$(id -u)" = "0" ] || { echo "run as root"; exit 1; }
command -v python3 >/dev/null || { echo "need python3"; exit 1; }
if ! python3 -c "import sys; assert sys.version_info >= (3,10)" 2>/dev/null; then
  echo "need python >= 3.10"; exit 1
fi
command -v docker >/dev/null || echo "note: no docker — containers page will be empty"
command -v nginx >/dev/null || echo "note: no nginx — install it for /term/ gating, else dashboard serves directly"

# --- packages ---
apt-get update -qq
apt-get install -y -qq python3 python3-venv nginx curl unzip tmux quota 2>/dev/null || \
apt-get install -y -qq python3 python3-venv nginx curl unzip tmux

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
mkdir -p "$DACH" "$DACH/data" "$DACH/term"
cp -r "$REPO_DIR/app" "$REPO_DIR/static" "$REPO_DIR/tunnel" "$DACH/"
cp -r "$REPO_DIR/term/." "$DACH/term/"
cp "$REPO_DIR/requirements.txt" "$DACH/"
[ -f "$DACH/config.yaml" ] || cp "$REPO_DIR/config.example.yaml" "$DACH/config.yaml"
chmod +x "$DACH"/tunnel/providers/*.sh

# --- venv ---
[ -d "$DACH/.venv" ] || python3 -m venv "$DACH/.venv"
"$DACH/.venv/bin/pip" install -q --upgrade pip
"$DACH/.venv/bin/pip" install -q -r "$DACH/requirements.txt"

# --- terminal web client: own xterm page (falls back to ttyd default) ---
XTERM_VER=5.5.0
FIT_VER=0.10.0
TERM_INDEX=""
mkdir -p "$DACH/term"
dl_ok=""
dl() { curl -sL --max-time 90 "$1" -o "$2" && [ -s "$2" ]; }
if dl "https://cdn.jsdelivr.net/npm/@xterm/xterm@${XTERM_VER}/lib/xterm.js" "$DACH/term/xterm.js" \
&& dl "https://cdn.jsdelivr.net/npm/@xterm/xterm@${XTERM_VER}/css/xterm.css" "$DACH/term/xterm.css" \
&& dl "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@${FIT_VER}/lib/addon-fit.js" "$DACH/term/addon-fit.js"; then
  if python3 - "$REPO_DIR/term/client.template.html" "$DACH/term" <<'EOF'; then
import sys
tpl, outdir = sys.argv[1], sys.argv[2]
page = open(tpl).read()
for key, name in (("__XTERM_CSS__", "xterm.css"), ("__XTERM_JS__", "xterm.js"),
                  ("__FIT_JS__", "addon-fit.js")):
    with open(f"{outdir}/{name}") as f:
        page = page.replace(key, f.read(), 1)
assert "__XTERM_" not in page and "__FIT_" not in page, "placeholders left"
open(f"{outdir}/index.html", "w").write(page)
print("term client built")
EOF
    TERM_INDEX="--index $DACH/term/index.html"
  else
    echo "term client build failed, ttyd default page"
  fi
else
  echo "xterm download failed, ttyd default page"
fi

# --- user slots ---
i=0
for slot in u-c1 u-c2 u-c3 u-c4; do
  if ! id "$slot" >/dev/null 2>&1; then
    useradd -m -s /usr/sbin/nologin "$slot"
    echo "created linux user $slot"
  fi
  port=$((PORT_BASE + i)); i=$((i + 1))
  # per-slot ttyd unit
  sed -e "s/%i/$slot/g" -e "s/PORT/$port/" -e "s|INDEX|$TERM_INDEX|" \
    "$REPO_DIR/deploy/systemd/dach-ttyd-slot.service.template" \
    > "/etc/systemd/system/dach-ttyd-${slot}.service"
  systemctl enable "dach-ttyd-${slot}.service" >/dev/null
  # nginx per-slot term + auth blocks (static X-Slot: nginx mangles
  # query strings in auth_request on some versions, so no ?args there)
  mkdir -p /etc/nginx/dachboard
  cat > "/etc/nginx/dachboard/term-${slot}.conf" <<EOF
location = /dash-auth-${slot} {
    internal;
    proxy_pass http://127.0.0.1:8420/api/auth-check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Cookie \$http_cookie;
    proxy_set_header X-Target term;
    proxy_set_header X-Slot ${slot};
}
# interactive shell: no buffering, no Nagle, long-lived socket
location /term/${slot}/ {
    auth_request /dash-auth-${slot};
    proxy_pass http://127.0.0.1:${port}/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_buffering off;
    proxy_cache off;
    tcp_nodelay on;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}
EOF
done

# --- filesystem quotas: hard per-user caps, automatic on ext4 ---
FSTYPE=$(findmnt -n -o FSTYPE / 2>/dev/null || echo unknown)
if [ "$FSTYPE" = "ext4" ]; then
  echo "enabling usrquota on / ..."
  python3 - <<'EOF' || echo "fstab edit skipped"
import shutil
p = '/etc/fstab'
shutil.copy(p, '/etc/fstab.dachbak')
lines = open(p).read().splitlines(keepends=True)
out = []
for ln in lines:
    s = ln.strip()
    if s and not s.startswith('#'):
        parts = s.split()
        if len(parts) >= 4 and parts[1] == '/' and 'usrquota' not in parts[3].split(','):
            parts[3] += ',usrquota'
            ln = '\t'.join(parts) + '\n'
    out.append(ln)
open(p, 'w').writelines(out)
print('fstab ok')
EOF
  mount -o remount / 2>/dev/null || echo "remount now failed (applies after reboot)"
  quotacheck -cum / 2>&1 | tail -1 || true
  quotaon / 2>&1 || true
  systemctl enable quotaon 2>/dev/null || true
else
  echo "note: / is $FSTYPE, not ext4 — hard quotas skipped (dashboard still shows soft usage)"
fi

# --- root shell unit + nginx block (admin only, gated by dashboard session) ---
ROOT_PORT=$((PORT_BASE - 1))
sed -e "s/PORT/$ROOT_PORT/" -e "s|INDEX|$TERM_INDEX|" \
  "$REPO_DIR/deploy/systemd/dach-ttyd-root.service.template" \
  > /etc/systemd/system/dach-ttyd-root.service
systemctl enable dach-ttyd-root.service >/dev/null
cat > /etc/nginx/dachboard/term-root.conf <<EOF
location = /dash-auth-root {
    internal;
    proxy_pass http://127.0.0.1:8420/api/auth-check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Cookie \$http_cookie;
    proxy_set_header X-Target term;
    proxy_set_header X-Slot root;
}
location /term/root/ {
    auth_request /dash-auth-root;
    proxy_pass http://127.0.0.1:${ROOT_PORT}/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_buffering off;
    proxy_cache off;
    tcp_nodelay on;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}
EOF

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
echo "1. start:  sudo systemctl start dachboard.service"
echo "2. token:  sudo journalctl -u dachboard -n 5 | grep 'SETUP TOKEN'"
echo "3. open http://127.0.0.1:8420 (or your tunnel URL) -> first-setup card"
echo "4. tunnel: bash deploy/tunnel-cloudflared.sh   (see TUNNEL.md for options)"
echo "5. loopback check: curl http://127.0.0.1:8420/api/setup-needed"
