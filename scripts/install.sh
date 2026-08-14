#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "Run this installer as root on a Proxmox VE host." >&2; exit 1; fi
if ! command -v pveversion >/dev/null 2>&1; then echo "This host does not appear to be Proxmox VE." >&2; exit 1; fi
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
install -d -m 0750 -o root -g proxmox-mcp /etc/proxmox-mcp-bridge/pki
install -m 0640 -o root -g proxmox-mcp /etc/pve/pve-root-ca.pem /etc/proxmox-mcp-bridge/pki/pve-root-ca.pem
ENV_FILE=/etc/proxmox-mcp-bridge/service.env
if [[ ! -f "$ENV_FILE" ]]; then
  TOKEN_JSON=$(pveum user token add mcp-bridge@pve service --privsep 0 --output-format json)
  TOKEN_SECRET=$(node -e 'const value=JSON.parse(process.argv[1]); process.stdout.write(value.value || value.token || "")' "$TOKEN_JSON")
  if [[ -z "$TOKEN_SECRET" ]]; then echo "Could not extract the new Proxmox API token secret." >&2; exit 1; fi
  cat >"$ENV_FILE" <<EOF
PMCP_PVE_TOKEN_ID=mcp-bridge@pve!service
PMCP_PVE_TOKEN_SECRET=$TOKEN_SECRET
PMCP_PVE_CA_FILE=/etc/proxmox-mcp-bridge/pki/pve-root-ca.pem
PMCP_TOOL_MODE=hybrid
PMCP_HTTP_HOST=127.0.0.1
PMCP_HTTP_PORT=8765
PMCP_LAN_HOST=192.168.1.100
PMCP_LAN_PORT=9444
PMCP_ALLOWED_HOSTS=127.0.0.1,localhost,infra,proxmox.example-tailnet.ts.net,192.168.1.100
PMCP_ALLOWED_ORIGINS=proxmox.example-tailnet.ts.net,192.168.1.100,localhost,127.0.0.1
PMCP_PROTECTED_PATHS=/mnt/model-repo,/dev/pve/model-repo,/dev/mapper/pve-model--repo
PMCP_PROTECTED_IDENTIFIERS=model-repo,pve/model-repo,pve-model--repo
EOF
  chown root:proxmox-mcp "$ENV_FILE"
  chmod 0640 "$ENV_FILE"
fi
if [[ ! -f /etc/proxmox-mcp-bridge/helper-secret ]]; then
  openssl rand -hex 32 >/etc/proxmox-mcp-bridge/helper-secret
  chown root:root /etc/proxmox-mcp-bridge/helper-secret
  chmod 0600 /etc/proxmox-mcp-bridge/helper-secret
fi
PKI_DIR=/etc/proxmox-mcp-bridge/pki
if [[ ! -f "$PKI_DIR/ca.crt" || ! -f "$PKI_DIR/server.crt" || ! -f "$PKI_DIR/server.key" ]]; then
  openssl genrsa -out "$PKI_DIR/ca.key" 4096
  openssl req -x509 -new -nodes -key "$PKI_DIR/ca.key" -sha256 -days 3650 -subj "/CN=Proxmox MCP Local CA" -out "$PKI_DIR/ca.crt"
  openssl genrsa -out "$PKI_DIR/server.key" 3072
  openssl req -new -key "$PKI_DIR/server.key" -subj "/CN=infra" -out "$PKI_DIR/server.csr"
  cat >"$PKI_DIR/server.ext" <<EOF
subjectAltName=DNS:infra,DNS:proxmox.example-tailnet.ts.net,IP:192.168.1.100,IP:100.64.0.10
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF
  openssl x509 -req -in "$PKI_DIR/server.csr" -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" -CAcreateserial -out "$PKI_DIR/server.crt" -days 825 -sha256 -extfile "$PKI_DIR/server.ext"
  rm -f "$PKI_DIR/server.csr" "$PKI_DIR/server.ext" "$PKI_DIR/ca.srl"
  chown -R root:proxmox-mcp "$PKI_DIR"
  chmod 0750 "$PKI_DIR"
  chmod 0640 "$PKI_DIR/server.key" "$PKI_DIR/server.crt" "$PKI_DIR/ca.crt"
  chmod 0600 "$PKI_DIR/ca.key"
fi
for unit in "$SOURCE_DIR"/systemd/*; do install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"; done
systemctl daemon-reload
systemctl enable --now proxmox-mcp-helper.service proxmox-mcp.service proxmox-mcp-schema.path proxmox-mcp-breakglass.path
if [[ ! -s /var/lib/proxmox-mcp-bridge/keys.json ]]; then
  /usr/bin/node /opt/proxmox-mcp-bridge/dist/cli.js key create --name initial-root --profile root >/root/proxmox-mcp-initial-key.json
  chmod 0600 /root/proxmox-mcp-initial-key.json
  chown -R proxmox-mcp:proxmox-mcp /var/lib/proxmox-mcp-bridge /var/log/proxmox-mcp-bridge
  systemctl restart proxmox-mcp.service
fi
if command -v tailscale >/dev/null 2>&1; then tailscale serve --bg --https=443 --set-path /mcp http://127.0.0.1:8765/mcp; fi
echo "Installed Proxmox MCP Bridge."
echo "Initial root key record: /root/proxmox-mcp-initial-key.json (mode 0600)"
echo "Tailnet endpoint: https://proxmox.example-tailnet.ts.net/mcp"
echo "LAN endpoint: https://192.168.1.100:9444/mcp"
echo "LAN CA certificate: /etc/proxmox-mcp-bridge/pki/ca.crt"
