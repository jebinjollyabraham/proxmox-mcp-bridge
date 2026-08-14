#!/usr/bin/env bash
set -euo pipefail

die() { echo "Error: $*" >&2; exit 1; }
join_by() { local IFS="$1"; shift; echo "$*"; }
is_private_ipv4() {
  [[ $1 =~ ^10\.([0-9]{1,3}\.){2}[0-9]{1,3}$ ]] ||
    [[ $1 =~ ^192\.168\.([0-9]{1,3}\.)[0-9]{1,3}$ ]] ||
    [[ $1 =~ ^172\.(1[6-9]|2[0-9]|3[01])\.([0-9]{1,3}\.)[0-9]{1,3}$ ]]
}
detect_lan_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]\+\).*/\1/p' | head -n1
}

[[ ${EUID} -eq 0 ]] || die "Run this installer as root on a Proxmox VE host."
command -v pveversion >/dev/null 2>&1 || die "This host does not appear to be Proxmox VE."

SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git nodejs npm ca-certificates openssl
cd "$SOURCE_DIR"
npm ci
npm run build

getent group proxmox-mcp >/dev/null || groupadd --system proxmox-mcp
id -u proxmox-mcp >/dev/null 2>&1 || useradd --system --gid proxmox-mcp --home-dir /var/lib/proxmox-mcp-bridge --shell /usr/sbin/nologin proxmox-mcp
install -d -m 0750 -o root -g proxmox-mcp /etc/proxmox-mcp-bridge /etc/proxmox-mcp-bridge/pki
install -d -m 0750 -o proxmox-mcp -g proxmox-mcp /var/lib/proxmox-mcp-bridge /var/log/proxmox-mcp-bridge
install -d -m 0755 -o root -g root /opt/proxmox-mcp-bridge
rm -rf /opt/proxmox-mcp-bridge/dist /opt/proxmox-mcp-bridge/node_modules
cp -a "$SOURCE_DIR/dist" "$SOURCE_DIR/package.json" "$SOURCE_DIR/package-lock.json" /opt/proxmox-mcp-bridge/
cd /opt/proxmox-mcp-bridge
npm ci --omit=dev
chmod +x dist/cli.js dist/http.js dist/stdio.js dist/helper.js dist/breakglass-runner.js
ln -sfn /opt/proxmox-mcp-bridge/dist/cli.js /usr/local/bin/proxmox-mcp
ln -sfn /opt/proxmox-mcp-bridge/dist/stdio.js /usr/local/bin/proxmox-mcp-stdio

if ! pveum user list --output-format json | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.exit(JSON.parse(s).some(x=>x.userid==="mcp-bridge@pve")?0:1))'; then
  pveum user add mcp-bridge@pve --comment "Proxmox MCP Bridge service identity"
fi
pveum acl modify / --users mcp-bridge@pve --roles Administrator --propagate 1
install -m 0640 -o root -g proxmox-mcp /etc/pve/pve-root-ca.pem /etc/proxmox-mcp-bridge/pki/pve-root-ca.pem

ENV_FILE=/etc/proxmox-mcp-bridge/service.env
if [[ ! -f "$ENV_FILE" ]]; then
  SETUP_MODE=${PMCP_SETUP_MODE:-}
  if [[ -z "$SETUP_MODE" && -t 0 ]]; then
    echo "Choose how MCP clients will reach this Proxmox host:"
    echo "  1) Localhost only (safest default)"
    echo "  2) Tailscale"
    echo "  3) Private LAN HTTPS"
    echo "  4) Tailscale and private LAN HTTPS"
    read -r -p "Selection [1]: " selection
    case ${selection:-1} in
      1) SETUP_MODE=local ;;
      2) SETUP_MODE=tailscale ;;
      3) SETUP_MODE=lan ;;
      4) SETUP_MODE=both ;;
      *) die "Choose 1, 2, 3, or 4." ;;
    esac
  fi
  SETUP_MODE=${SETUP_MODE:-local}
  [[ $SETUP_MODE =~ ^(local|tailscale|lan|both)$ ]] || die "PMCP_SETUP_MODE must be local, tailscale, lan, or both."

  NODE_HOST=${PMCP_NODE_HOSTNAME:-$(hostname -s)}
  LAN_HOST=127.0.0.1
  TAILSCALE_HOST=""
  ENABLE_TAILSCALE=false
  ALLOWED_HOSTS=(127.0.0.1 localhost "$NODE_HOST")
  CERT_SANS=(DNS:localhost "DNS:$NODE_HOST" IP:127.0.0.1)

  if [[ $SETUP_MODE == lan || $SETUP_MODE == both ]]; then
    LAN_HOST=${PMCP_LAN_HOST:-$(detect_lan_ip)}
    [[ -n "$LAN_HOST" ]] || die "Could not detect a LAN address; set PMCP_LAN_HOST to this host's private IPv4 address."
    is_private_ipv4 "$LAN_HOST" || die "PMCP_LAN_HOST must be an RFC1918 private IPv4 address; public listeners are refused."
    ALLOWED_HOSTS+=("$LAN_HOST")
    CERT_SANS+=("IP:$LAN_HOST")
  fi

  if [[ $SETUP_MODE == tailscale || $SETUP_MODE == both ]]; then
    command -v tailscale >/dev/null 2>&1 || die "Tailscale mode requires Tailscale to be installed first: https://tailscale.com/download/linux"
    TS_STATUS=$(tailscale status --json 2>/dev/null) || die "Tailscale is installed but not active. Run 'tailscale up' first."
    TAILSCALE_HOST=${PMCP_TAILSCALE_HOST:-$(node -e 'const j=JSON.parse(process.argv[1]); process.stdout.write((j.Self?.DNSName||"").replace(/\.$/,""))' "$TS_STATUS")}
    [[ -n "$TAILSCALE_HOST" ]] || die "Could not detect the Tailscale DNS name; set PMCP_TAILSCALE_HOST."
    [[ $TAILSCALE_HOST == *.ts.net ]] || die "PMCP_TAILSCALE_HOST must be a Tailscale ts.net DNS name."
    ENABLE_TAILSCALE=true
    ALLOWED_HOSTS+=("$TAILSCALE_HOST")
    CERT_SANS+=("DNS:$TAILSCALE_HOST")
  fi

  TOKEN_JSON=$(pveum user token add mcp-bridge@pve service --privsep 0 --output-format json)
  TOKEN_SECRET=$(node -e 'const value=JSON.parse(process.argv[1]); process.stdout.write(value.value || value.token || "")' "$TOKEN_JSON")
  [[ -n "$TOKEN_SECRET" ]] || die "Could not extract the new Proxmox API token secret."
  ALLOWED=$(join_by , "${ALLOWED_HOSTS[@]}")
  cat >"$ENV_FILE" <<EOF
PMCP_PVE_TOKEN_ID=mcp-bridge@pve!service
PMCP_PVE_TOKEN_SECRET=$TOKEN_SECRET
PMCP_PVE_CA_FILE=/etc/proxmox-mcp-bridge/pki/pve-root-ca.pem
PMCP_PVE_TLS_SERVERNAME=$NODE_HOST
PMCP_TOOL_MODE=hybrid
PMCP_HTTP_HOST=127.0.0.1
PMCP_HTTP_PORT=8765
PMCP_LAN_HOST=$LAN_HOST
PMCP_LAN_PORT=9444
PMCP_ALLOWED_HOSTS=$ALLOWED
PMCP_ALLOWED_ORIGINS=$ALLOWED
PMCP_ENABLE_TAILSCALE=$ENABLE_TAILSCALE
PMCP_TAILSCALE_HOST=$TAILSCALE_HOST
PMCP_PROTECTED_PATHS=/mnt/model-repo,/dev/pve/model-repo,/dev/mapper/pve-model--repo
PMCP_PROTECTED_IDENTIFIERS=model-repo,pve/model-repo,pve-model--repo
EOF
  chown root:proxmox-mcp "$ENV_FILE"
  chmod 0640 "$ENV_FILE"

  PKI_DIR=/etc/proxmox-mcp-bridge/pki
  openssl genrsa -out "$PKI_DIR/ca.key" 4096
  openssl req -x509 -new -nodes -key "$PKI_DIR/ca.key" -sha256 -days 3650 -subj "/CN=Proxmox MCP Local CA" -out "$PKI_DIR/ca.crt"
  openssl genrsa -out "$PKI_DIR/server.key" 3072
  openssl req -new -key "$PKI_DIR/server.key" -subj "/CN=$NODE_HOST" -out "$PKI_DIR/server.csr"
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n' "$(join_by , "${CERT_SANS[@]}")" >"$PKI_DIR/server.ext"
  openssl x509 -req -in "$PKI_DIR/server.csr" -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" -CAcreateserial -out "$PKI_DIR/server.crt" -days 825 -sha256 -extfile "$PKI_DIR/server.ext"
  rm -f "$PKI_DIR/server.csr" "$PKI_DIR/server.ext" "$PKI_DIR/ca.srl"
  chown -R root:proxmox-mcp "$PKI_DIR"
  chmod 0750 "$PKI_DIR"
  chmod 0640 "$PKI_DIR/server.key" "$PKI_DIR/server.crt" "$PKI_DIR/ca.crt"
  chmod 0600 "$PKI_DIR/ca.key"
fi

if [[ ! -f /etc/proxmox-mcp-bridge/helper-secret ]]; then
  openssl rand -hex 32 >/etc/proxmox-mcp-bridge/helper-secret
  chown root:root /etc/proxmox-mcp-bridge/helper-secret
  chmod 0600 /etc/proxmox-mcp-bridge/helper-secret
fi

for unit in "$SOURCE_DIR"/systemd/*; do install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"; done
systemctl daemon-reload
systemctl enable proxmox-mcp-helper.service proxmox-mcp.service proxmox-mcp-schema.path proxmox-mcp-breakglass.path
systemctl restart proxmox-mcp-helper.service
systemctl restart proxmox-mcp.service
systemctl restart proxmox-mcp-schema.path proxmox-mcp-breakglass.path
if [[ ! -s /var/lib/proxmox-mcp-bridge/keys.json ]]; then
  /usr/bin/node /opt/proxmox-mcp-bridge/dist/cli.js key create --name initial-root --profile root >/root/proxmox-mcp-initial-key.json
  chmod 0600 /root/proxmox-mcp-initial-key.json
  chown -R proxmox-mcp:proxmox-mcp /var/lib/proxmox-mcp-bridge /var/log/proxmox-mcp-bridge
  systemctl restart proxmox-mcp.service
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
if [[ ${PMCP_ENABLE_TAILSCALE:-false} == true ]]; then
  command -v tailscale >/dev/null 2>&1 || die "Tailscale was configured but is no longer installed."
  tailscale serve --bg --https=443 --set-path /mcp http://127.0.0.1:8765/mcp
fi

echo "Installed Proxmox MCP Bridge."
echo "Initial root key record: /root/proxmox-mcp-initial-key.json (mode 0600)"
echo "Loopback endpoint: http://127.0.0.1:8765/mcp"
if [[ ${PMCP_ENABLE_TAILSCALE:-false} == true ]]; then echo "Tailnet endpoint: https://${PMCP_TAILSCALE_HOST}/mcp"; fi
if [[ ${PMCP_LAN_HOST:-127.0.0.1} != 127.0.0.1 ]]; then
  echo "Private-LAN endpoint: https://${PMCP_LAN_HOST}:${PMCP_LAN_PORT:-9444}/mcp"
  echo "LAN CA certificate: /etc/proxmox-mcp-bridge/pki/ca.crt"
fi
