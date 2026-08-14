#!/usr/bin/env node
import { config } from "./config.js";
import { KeyStore } from "./auth.js";
import { PolicyStore } from "./policy.js";
import { SchemaRegistry } from "./schema.js";
import type { BuiltinProfile } from "./types.js";
import { errorMessage } from "./util.js";
import { callHelper } from "./helper-client.js";
function flag(args: string[], name: string): string | undefined { const index = args.indexOf(`--${name}`); return index >= 0 ? args[index + 1] : undefined; }
function print(value: unknown): void { process.stdout.write(`${JSON.stringify(value, null, 2)}\n`); }
async function main(): Promise<void> {
  const [domain, command, ...args] = process.argv.slice(2); const keys = new KeyStore(config.keysFile);
  if (domain === "key" && command === "create") {
    const name = flag(args, "name"); const profile = flag(args, "profile") as BuiltinProfile | "custom" | undefined;
    if (!name || !profile || !["read-only", "operator", "admin", "root", "custom"].includes(profile)) throw new Error("Usage: proxmox-mcp key create --name NAME --profile read-only|operator|admin|root|custom [--policy ID] [--expires ISO]");
    print(await keys.create(name, profile, flag(args, "policy"), flag(args, "expires"))); return;
  }
  if (domain === "key" && command === "list") { print(await keys.list()); return; }
  if (domain === "key" && command === "rotate") { const target = args[0]; if (!target) throw new Error("Usage: proxmox-mcp key rotate ID_OR_NAME [--expires ISO]"); print(await keys.rotate(target, flag(args, "expires"))); return; }
  if (domain === "key" && command === "revoke") { const target = args[0]; if (!target) throw new Error("Usage: proxmox-mcp key revoke ID_OR_NAME"); print(await keys.revoke(target)); return; }
  if (domain === "policy" && command === "list") { print(await new PolicyStore(config.policiesFile, [...config.protectedPaths, ...config.protectedIdentifiers]).list()); return; }
  if (domain === "schema" && (command === "refresh" || command === "status")) { const registry = await SchemaRegistry.load(config.schemaSource, config.schemaCache); print(registry.snapshot); return; }
  if (domain === "doctor") {
    const registry = await SchemaRegistry.load(config.schemaSource, config.schemaCache); let helper: unknown;
    try { helper = await callHelper(config.helperSocket, "service_status", { service: "pveproxy.service" }); } catch (error) { helper = { error: errorMessage(error) }; }
    print({ schema: { source: registry.snapshot.source, hash: registry.snapshot.sha256, endpointCount: registry.snapshot.endpointCount, lastError: registry.snapshot.lastError ?? null }, helper, keys: (await keys.list()).length }); return;
  }
  throw new Error("Usage: proxmox-mcp key create|list|rotate|revoke | policy list | schema refresh|status | doctor");
}
main().catch((error) => { process.stderr.write(`${errorMessage(error)}\n`); process.exit(1); });
