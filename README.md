# Proxmox MCP Bridge

A policy-aware Model Context Protocol server for Proxmox VE. It maps the API schema installed on the host, provides compact and expanded MCP tool modes, supports Streamable HTTP and stdio, and adds guarded host command and filesystem operations.

This first release targets the `infra` Proxmox VE 9.1.1 host. Portability to other releases is experimental.

## Capabilities

- Complete API discovery, description, and invocation from the official local `apidoc.js` schema.
- Automatic schema refresh after Proxmox updates with last-known-good fallback.
- Curated node, cluster, guest, storage, power, task, service, command, and file tools.
- Optional endpoint-per-tool expansion via `PMCP_TOOL_MODE=expanded`.
- Per-person `read-only`, `operator`, `admin`, `root`, or deterministic custom policies.
- Conversational onboarding through the `proxmox_onboarding` MCP prompt.
- Two-confirmation, one-operation, five-minute break-glass handling for the protected model repository.

## Install on Proxmox

```bash
git clone https://github.com/jebinjollyabraham/proxmox-mcp-bridge.git /root/tools/proxmox-mcp-bridge
cd /root/tools/proxmox-mcp-bridge
./scripts/install.sh
```

The installer creates a dedicated Proxmox service identity, system users, systemd units, a local TLS CA, and the first root-profile MCP key. Its one-time plaintext is written to `/root/proxmox-mcp-initial-key.json` with mode `0600`; only the scrypt hash remains in bridge state.

Endpoints:

- Tailnet: `https://proxmox.example-tailnet.ts.net/mcp`
- Office LAN: `https://192.168.1.100:9444/mcp`
- Loopback: `http://127.0.0.1:8765/mcp`

The installer adds the Tailnet `/mcp` route without resetting other Tailscale Serve routes. LAN clients must trust `/etc/proxmox-mcp-bridge/pki/ca.crt`.

## Key management

```bash
proxmox-mcp key create --name alice --profile read-only
proxmox-mcp key create --name operator --profile operator --expires 2027-01-01T00:00:00Z
proxmox-mcp key list
proxmox-mcp key revoke alice
```

Key secrets are returned once. Use the onboarding and policy tools to create a custom policy, activate its digest, then bind a key with `--profile custom --policy POLICY_ID`.

## Automatic API alignment

At startup the bridge extracts only the JSON array assigned to `const apiSchema` in `/usr/share/pve-docs/api-viewer/apidoc.js`; it never evaluates JavaScript. The normalized registry records method, template path, parameter and return schemas, permissions, token support, risk, and a deterministic expanded tool name.

`proxmox-mcp-schema.path` watches the official schema. A valid update replaces the cache and restarts the bridge. A malformed update leaves the last-known-good cache active and surfaces the error through `proxmox_schema_status` and `/healthz`.

## Safety boundary

No installation or test command writes to or deletes `/mnt/model-repo` or its logical volume. Ordinary bridge processes see the model mount read-only and known model block-device paths hidden. Model mutation requires an exact structured operation, two separate confirmation phrases, and a signed one-shot root runner.

A root MCP key remains equivalent to a highly privileged automation credential. Read [the security model](docs/SECURITY.md) before distributing one.

## Development

```bash
npm ci
npm test
```

The tests cover schema extraction, deterministic expanded names, key hashing and revocation, policy precedence, and the model guard. The real model repository is never used as a destructive test target.

## License

Apache-2.0
