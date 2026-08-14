import { randomBytes, randomUUID } from "node:crypto";
import type { JsonObject, PolicyAction } from "./types.js";
import { atomicWriteJson, canonicalJson, readJson, sha256 } from "./util.js";

interface PendingConfirmation { id: string; keyId: string; action: PolicyAction; operation: JsonObject; digest: string; expiresAt: string }
interface BreakglassApproval { id: string; keyId: string; operation: JsonObject; digest: string; stage: 0 | 1 | 2 | 3; nonce1: string; nonce2?: string; expiresAt: string }

export class ConfirmationStore {
  constructor(private readonly filename: string) {}
  private async load(): Promise<PendingConfirmation[]> { return readJson<PendingConfirmation[]>(this.filename, []); }
  async create(keyId: string, action: PolicyAction, operation: JsonObject): Promise<PendingConfirmation> {
    const digest = sha256(canonicalJson({ keyId, action, operation }));
    const pending: PendingConfirmation = { id: randomUUID(), keyId, action, operation, digest, expiresAt: new Date(Date.now() + 5 * 60_000).toISOString() };
    const items = (await this.load()).filter((item) => Date.parse(item.expiresAt) > Date.now()); items.push(pending); await atomicWriteJson(this.filename, items, 0o640); return pending;
  }
  async consume(id: string, keyId: string, confirmation: string): Promise<PendingConfirmation> {
    const items = await this.load(); const pending = items.find((item) => item.id === id && item.keyId === keyId);
    if (!pending) throw new Error("Pending confirmation was not found for this API key");
    if (Date.parse(pending.expiresAt) <= Date.now()) throw new Error("Pending confirmation expired");
    const required = `EXECUTE ${pending.digest.slice(0, 12)}`;
    if (confirmation !== required) throw new Error(`Confirmation must exactly equal '${required}'`);
    await atomicWriteJson(this.filename, items.filter((item) => item.id !== id), 0o640); return pending;
  }
}

export class BreakglassStore {
  constructor(private readonly filename: string) {}
  private async load(): Promise<BreakglassApproval[]> { return readJson<BreakglassApproval[]>(this.filename, []); }
  private async save(items: BreakglassApproval[]): Promise<void> { await atomicWriteJson(this.filename, items, 0o640); }
  async prepare(keyId: string, operation: JsonObject): Promise<BreakglassApproval> {
    const digest = sha256(canonicalJson({ keyId, operation }));
    const approval: BreakglassApproval = { id: randomUUID(), keyId, operation, digest, stage: 0, nonce1: randomBytes(12).toString("hex"), expiresAt: new Date(Date.now() + 5 * 60_000).toISOString() };
    const items = (await this.load()).filter((item) => Date.parse(item.expiresAt) > Date.now()); items.push(approval); await this.save(items); return approval;
  }
  async confirmFirst(id: string, keyId: string, confirmation: string): Promise<BreakglassApproval> {
    const items = await this.load(); const approval = items.find((item) => item.id === id && item.keyId === keyId);
    if (!approval || approval.stage !== 0) throw new Error("Break-glass approval is missing or not awaiting first confirmation");
    if (Date.parse(approval.expiresAt) <= Date.now()) throw new Error("Break-glass approval expired");
    const required = `CONFIRM 1 ${approval.digest.slice(0, 12)} ${approval.nonce1}`;
    if (confirmation !== required) throw new Error(`First confirmation must exactly equal '${required}'`);
    approval.stage = 1; approval.nonce2 = randomBytes(12).toString("hex"); await this.save(items); return approval;
  }
  async confirmSecond(id: string, keyId: string, confirmation: string): Promise<BreakglassApproval> {
    const items = await this.load(); const approval = items.find((item) => item.id === id && item.keyId === keyId);
    if (!approval || approval.stage !== 1 || !approval.nonce2) throw new Error("Break-glass approval is not awaiting second confirmation");
    const required = `CONFIRM 2 ${approval.digest.slice(0, 12)} ${approval.nonce2}`;
    if (confirmation !== required) throw new Error(`Second confirmation must exactly equal '${required}'`);
    approval.stage = 2; await this.save(items); return approval;
  }
  async consume(id: string, keyId: string): Promise<BreakglassApproval> {
    const items = await this.load(); const approval = items.find((item) => item.id === id && item.keyId === keyId);
    if (!approval || approval.stage !== 2) throw new Error("Break-glass approval has not completed both confirmations");
    if (Date.parse(approval.expiresAt) <= Date.now()) throw new Error("Break-glass approval expired");
    approval.stage = 3; await this.save(items.filter((item) => item.id !== id)); return approval;
  }
}
