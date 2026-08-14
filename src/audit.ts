import { appendFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { JsonValue, Principal } from "./types.js";
import { canonicalJson, sha256 } from "./util.js";

export interface AuditEvent {
  principal: Principal; action: string; resource: string; outcome: "allowed" | "denied" | "pending" | "error"; durationMs: number; details?: JsonValue;
}

export class AuditLog {
  constructor(private readonly filename: string) {}
  async write(event: AuditEvent): Promise<void> {
    await mkdir(path.dirname(this.filename), { recursive: true });
    const record = {
      timestamp: new Date().toISOString(), keyId: event.principal.keyId, principal: event.principal.name,
      profile: event.principal.profile, sourceIp: event.principal.sourceIp ?? null, action: event.action,
      resource: event.resource, outcome: event.outcome, durationMs: event.durationMs,
      detailsDigest: event.details ? sha256(canonicalJson(event.details)) : null
    };
    await appendFile(this.filename, `${JSON.stringify(record)}\n`, { mode: 0o640 });
  }
  async tail(limit: number): Promise<JsonValue> {
    try {
      const lines = (await readFile(this.filename, "utf8")).trim().split("\n").filter(Boolean);
      return lines.slice(-limit).map((line) => JSON.parse(line) as JsonValue);
    } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return []; throw error; }
  }
}
