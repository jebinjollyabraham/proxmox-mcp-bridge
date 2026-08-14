import path from "node:path";

function integer(name: string, fallback: number): number {
  const value = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isFinite(value) ? value : fallback;
}

function list(name: string, fallback: string[]): string[] {
  const value = process.env[name];
  return value ? value.split(",").map((item) => item.trim()).filter(Boolean) : fallback;
}

const configDir = process.env.PMCP_CONFIG_DIR ?? "/etc/proxmox-mcp-bridge";
const stateDir = process.env.PMCP_STATE_DIR ?? "/var/lib/proxmox-mcp-bridge";

export const config = {
  configDir,
  stateDir,
  schemaSource: process.env.PMCP_SCHEMA_SOURCE ?? "/usr/share/pve-docs/api-viewer/apidoc.js",
  schemaCache: process.env.PMCP_SCHEMA_CACHE ?? path.join(stateDir, "api-registry.json"),
  keysFile: process.env.PMCP_KEYS_FILE ?? path.join(stateDir, "keys.json"),
  policiesFile: process.env.PMCP_POLICIES_FILE ?? path.join(stateDir, "policies.json"),
  confirmationsFile: process.env.PMCP_CONFIRMATIONS_FILE ?? path.join(stateDir, "confirmations.json"),
  breakglassFile: process.env.PMCP_BREAKGLASS_FILE ?? path.join(stateDir, "breakglass.json"),
  auditFile: process.env.PMCP_AUDIT_FILE ?? "/var/log/proxmox-mcp-bridge/audit.jsonl",
  helperSocket: process.env.PMCP_HELPER_SOCKET ?? "/run/proxmox-mcp-bridge/helper.sock",
  helperSecretFile: process.env.PMCP_HELPER_SECRET_FILE ?? path.join(configDir, "helper-secret"),
  breakglassRequest: process.env.PMCP_BREAKGLASS_REQUEST ?? "/run/proxmox-mcp-bridge/breakglass-request.json",
  breakglassResult: process.env.PMCP_BREAKGLASS_RESULT ?? "/run/proxmox-mcp-bridge/breakglass-result.json",
  breakglassUsedFile: process.env.PMCP_BREAKGLASS_USED_FILE ?? path.join(stateDir, "breakglass-used.json"),
  httpHost: process.env.PMCP_HTTP_HOST ?? "127.0.0.1",
  httpPort: integer("PMCP_HTTP_PORT", 8765),
  lanHost: process.env.PMCP_LAN_HOST ?? "192.168.1.100",
  lanPort: integer("PMCP_LAN_PORT", 9444),
  tlsCert: process.env.PMCP_TLS_CERT ?? path.join(configDir, "pki", "server.crt"),
  tlsKey: process.env.PMCP_TLS_KEY ?? path.join(configDir, "pki", "server.key"),
  allowedHosts: list("PMCP_ALLOWED_HOSTS", ["127.0.0.1", "localhost", "infra", "proxmox.example-tailnet.ts.net", "192.168.1.100"]),
  allowedOrigins: list("PMCP_ALLOWED_ORIGINS", ["proxmox.example-tailnet.ts.net", "192.168.1.100", "localhost", "127.0.0.1"]),
  toolMode: process.env.PMCP_TOOL_MODE ?? "hybrid",
  responseCharacterLimit: integer("PMCP_RESPONSE_CHARACTER_LIMIT", 25000),
  requestLimitBytes: integer("PMCP_REQUEST_LIMIT_BYTES", 1048576),
  rateLimitPerMinute: integer("PMCP_RATE_LIMIT_PER_MINUTE", 120),
  pveEndpoint: process.env.PMCP_PVE_ENDPOINT ?? "https://127.0.0.1:8006/api2/json",
  pveTokenId: process.env.PMCP_PVE_TOKEN_ID,
  pveTokenSecret: process.env.PMCP_PVE_TOKEN_SECRET,
  pveCaFile: process.env.PMCP_PVE_CA_FILE ?? "/etc/pve/pve-root-ca.pem",
  pveTlsServername: process.env.PMCP_PVE_TLS_SERVERNAME ?? "infra",
  protectedPaths: list("PMCP_PROTECTED_PATHS", ["/mnt/model-repo", "/dev/pve/model-repo", "/dev/mapper/pve-model--repo"]),
  protectedIdentifiers: list("PMCP_PROTECTED_IDENTIFIERS", ["model-repo", "pve/model-repo", "pve-model--repo"])
} as const;
