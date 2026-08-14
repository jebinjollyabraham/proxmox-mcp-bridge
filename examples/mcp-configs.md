# Harness configuration examples

Replace `${PROXMOX_MCP_KEY}` through the harness's secret or environment mechanism. Do not paste a real key into a committed configuration file.

## Generic Streamable HTTP

```json
{
  "name": "office-proxmox",
  "transport": "streamable-http",
  "url": "https://proxmox.example-tailnet.ts.net/mcp",
  "headers": { "Authorization": "Bearer ${PROXMOX_MCP_KEY}" }
}
```

## Office LAN

Trust `/etc/proxmox-mcp-bridge/pki/ca.crt` on the client, then use `https://192.168.1.100:9444/mcp` with the same bearer header.

## Local stdio

```json
{ "command": "/usr/local/bin/proxmox-mcp-stdio", "args": [] }
```

Local stdio is root-profile access and should only be configured for trusted local harnesses.
