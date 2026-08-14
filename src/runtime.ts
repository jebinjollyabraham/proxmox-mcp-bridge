import { config } from "./config.js";
import { SchemaRegistry } from "./schema.js";
import { PolicyStore } from "./policy.js";
import { KeyStore } from "./auth.js";
import { AuditLog } from "./audit.js";
import { ProxmoxClient } from "./proxmox.js";
import { BreakglassStore, ConfirmationStore } from "./confirmations.js";
import type { ServerDependencies } from "./tools.js";

export async function loadDependencies(): Promise<ServerDependencies> {
  const registry = await SchemaRegistry.load(config.schemaSource, config.schemaCache);
  return {
    registry,
    policies: new PolicyStore(config.policiesFile, [...config.protectedPaths, ...config.protectedIdentifiers]),
    keys: new KeyStore(config.keysFile), audit: new AuditLog(config.auditFile),
    proxmox: new ProxmoxClient({ baseUrl: config.pveEndpoint, ...(config.pveTokenId ? { tokenId: config.pveTokenId } : {}), ...(config.pveTokenSecret ? { tokenSecret: config.pveTokenSecret } : {}), caFile: config.pveCaFile, tlsServername: config.pveTlsServername, helperSocket: config.helperSocket }),
    confirmations: new ConfirmationStore(config.confirmationsFile), breakglass: new BreakglassStore(config.breakglassFile)
  };
}
