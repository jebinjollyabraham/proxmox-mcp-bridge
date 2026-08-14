import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import type { BuiltinProfile, Principal } from "./types.js";
import { atomicWriteJson, readJson } from "./util.js";

export interface ApiKeyRecord {
  id: string; name: string; profile: BuiltinProfile | "custom"; policyId?: string;
  salt: string; hash: string; createdAt: string; expiresAt?: string; revokedAt?: string;
}
interface KeyDatabase { version: 1; keys: ApiKeyRecord[] }
function derive(secret: string, salt: string): Buffer { return scryptSync(secret, Buffer.from(salt, "base64url"), 32); }

export class KeyStore {
  constructor(private readonly filename: string) {}
  private async load(): Promise<KeyDatabase> { return readJson<KeyDatabase>(this.filename, { version: 1, keys: [] }); }
  private async save(database: KeyDatabase): Promise<void> { await atomicWriteJson(this.filename, database, 0o640); }
  async create(name: string, profile: BuiltinProfile | "custom", policyId?: string, expiresAt?: string): Promise<{ secret: string; record: ApiKeyRecord }> {
    if (profile === "custom" && !policyId) throw new Error("Custom keys require an active policy ID");
    const secret = `pmcp_${randomBytes(32).toString("base64url")}`;
    const salt = randomBytes(24).toString("base64url");
    const record: ApiKeyRecord = {
      id: randomUUID(), name, profile, ...(policyId ? { policyId } : {}), salt,
      hash: derive(secret, salt).toString("base64url"), createdAt: new Date().toISOString(), ...(expiresAt ? { expiresAt } : {})
    };
    const database = await this.load(); database.keys.push(record); await this.save(database); return { secret, record };
  }
  async verify(secret: string, sourceIp?: string): Promise<Principal | null> {
    if (!secret.startsWith("pmcp_")) return null;
    const database = await this.load(); const now = Date.now();
    for (const record of database.keys) {
      if (record.revokedAt || (record.expiresAt && Date.parse(record.expiresAt) <= now)) continue;
      const actual = derive(secret, record.salt); const expected = Buffer.from(record.hash, "base64url");
      if (actual.length === expected.length && timingSafeEqual(actual, expected)) {
        return { keyId: record.id, name: record.name, profile: record.profile, ...(record.policyId ? { policyId: record.policyId } : {}), ...(sourceIp ? { sourceIp } : {}) };
      }
    }
    return null;
  }
  async list(): Promise<Array<Omit<ApiKeyRecord, "salt" | "hash">>> {
    return (await this.load()).keys.map(({ salt: _salt, hash: _hash, ...record }) => record);
  }
  async revoke(idOrName: string): Promise<ApiKeyRecord> {
    const database = await this.load(); const record = database.keys.find((item) => item.id === idOrName || item.name === idOrName);
    if (!record) throw new Error(`API key '${idOrName}' was not found`);
    record.revokedAt = new Date().toISOString(); await this.save(database); return record;
  }
}
