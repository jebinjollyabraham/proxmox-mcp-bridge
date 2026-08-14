#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi
systemctl disable --now proxmox-mcp.service proxmox-mcp-helper.service proxmox-mcp-schema.path proxmox-mcp-breakglass.path 2>/dev/null || true
rm -f /etc/systemd/system/proxmox-mcp.service /etc/systemd/system/proxmox-mcp-helper.service /etc/systemd/system/proxmox-mcp-schema.path /etc/systemd/system/proxmox-mcp-schema.service /etc/systemd/system/proxmox-mcp-breakglass.path /etc/systemd/system/proxmox-mcp-breakglass.service
rm -f /usr/local/bin/proxmox-mcp /usr/local/bin/proxmox-mcp-stdio
systemctl daemon-reload
echo "Runtime services removed. Configuration, keys, audit records, PVE identity, and all storage were preserved."
