#!/usr/bin/env bash
set -euo pipefail
systemctl --no-pager --full status proxmox-mcp.service proxmox-mcp-helper.service || true
/usr/local/bin/proxmox-mcp doctor
tailscale serve status --json 2>/dev/null || true
ss -lntp | grep -E ':(8765|9444)\b' || true
