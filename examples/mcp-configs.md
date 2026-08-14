# Harness configuration examples

Replace `${PROXMOX_MCP_KEY}` through the harness's secret or environment mechanism. Do not paste a real key into a committed configuration file.

## Generic Streamable HTTP

```json
{
  "name": "proxmox",
  "transport": "streamable-http",
  "url": "https://your-proxmox-host.your-tailnet.ts.net/mcp",
  "headers": { "Authorization": "Bearer ${PROXMOX_MCP_KEY}" }
}
```

The hostname is printed by the installer when Tailscale mode is selected. Tailscale controls network reachability; the bearer key still authenticates the MCP client.

## Private LAN

Trust `/etc/proxmox-mcp-bridge/pki/ca.crt` on the client, then use `https://192.168.1.100:9444/mcp` with the same bearer header. Replace the example address with the private address selected during installation.

## Codex

Keep the key in an environment variable instead of writing it into `config.toml`:

```toml
[mcp_servers.proxmox]
url = "https://your-proxmox-host.your-tailnet.ts.net/mcp"
bearer_token_env_var = "PROXMOX_MCP_BEARER_TOKEN"
```

## Local stdio

```json
{ "command": "/usr/local/bin/proxmox-mcp-stdio", "args": [] }
```

Local stdio is root-profile access and should only be configured for trusted local harnesses.
