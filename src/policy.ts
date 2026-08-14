import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { JsonValue, PolicyAction, PolicyDecision, PolicyEffect, Principal } from "./types.js";
import { atomicWriteJson, canonicalJson, readJson, sha256 } from "./util.js";

const EffectSchema = z.enum(["allow", "deny", "confirm", "breakglass"]);
const TimeWindowSchema = z.object({
  days: z.array(z.number().int().min(0).max(6)).optional(),
  start: z.string().regex(/^\d{2}:\d{2}$/),
  end: z.string().regex(/^\d{2}:\d{2}$/)
}).strict();

export const PolicyRuleSchema = z.object({
  id: z.string().min(1).max(100),
  effect: EffectSchema,
  actions: z.array(z.string().min(1)).min(1),
  resources: z.array(z.string()).optional(),
  methods: z.array(z.enum(["GET", "POST", "PUT", "DELETE"])).optional(),
  vmids: z.array(z.number().int().positive()).optional(),
  storageIds: z.array(z.string()).optional(),
  executables: z.array(z.string()).optional(),
  services: z.array(z.string()).optional(),
  sourceNetworks: z.array(z.string()).optional(),
  timeWindows: z.array(TimeWindowSchema).optional(),
  description: z.string().max(500).optional()
}).strict();

export const PolicyDocumentSchema = z.object({
  name: z.string().min(1).max(120),
  defaultEffect: EffectSchema.default("deny"),
  sourceRules: z.string().max(10000),
  rules: z.array(PolicyRuleSchema).max(250)
}).strict();

export type PolicyDocumentInput = z.infer<typeof PolicyDocumentSchema>;
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export interface StoredPolicy extends PolicyDocumentInput {
  id: string; version: number; digest: string; createdAt: string; active: boolean;
}
interface PolicyDraft { id: string; document: PolicyDocumentInput; digest: string; createdAt: string; warnings: string[] }
interface PolicyDatabase { version: 1; policies: StoredPolicy[]; drafts: PolicyDraft[] }

const EFFECT_RANK: Record<PolicyEffect, number> = { allow: 0, confirm: 1, breakglass: 2, deny: 3 };
const READ_ONLY_EXECUTABLES = new Set(["cat", "df", "du", "file", "find", "grep", "head", "ls", "rg", "sha256sum", "stat", "tail", "wc"]);

function glob(pattern: string, value: string): boolean {
  const doubleToken = "\u0000";
  const escaped = pattern.replace(/[-/\\^$+?.()|[\]{}]/g, "\\$&").replaceAll("**", doubleToken).replaceAll("*", "[^/]*").replaceAll(doubleToken, ".*");
  return new RegExp(`^${escaped}$`, "i").test(value);
}

function ipv4ToInt(address: string): number | null {
  const pieces = address.replace(/^::ffff:/, "").split(".");
  if (pieces.length !== 4) return null;
  const numbers = pieces.map(Number);
  if (numbers.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((numbers[0] ?? 0) << 24) | ((numbers[1] ?? 0) << 16) | ((numbers[2] ?? 0) << 8) | (numbers[3] ?? 0)) >>> 0;
}

function inNetwork(address: string, network: string): boolean {
  const [base, prefixText = "32"] = network.split("/");
  const value = ipv4ToInt(address); const baseValue = ipv4ToInt(base ?? ""); const prefix = Number(prefixText);
  if (value === null || baseValue === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return address === network;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (baseValue & mask);
}

function withinWindow(window: z.infer<typeof TimeWindowSchema>, now = new Date()): boolean {
  if (window.days && !window.days.includes(now.getDay())) return false;
  const minutes = now.getHours() * 60 + now.getMinutes();
  const toMinutes = (time: string): number => { const [hours = "0", mins = "0"] = time.split(":"); return Number(hours) * 60 + Number(mins); };
  const start = toMinutes(window.start); const end = toMinutes(window.end);
  return start <= end ? minutes >= start && minutes <= end : minutes >= start || minutes <= end;
}

function ruleMatches(rule: PolicyRule, action: PolicyAction): boolean {
  if (!rule.actions.some((pattern) => glob(pattern, action.action))) return false;
  if (rule.resources && !rule.resources.some((pattern) => glob(pattern, action.resource))) return false;
  if (rule.methods && (!action.method || !rule.methods.includes(action.method))) return false;
  if (rule.vmids && (!action.vmid || !rule.vmids.includes(action.vmid))) return false;
  if (rule.storageIds && (!action.storageId || !rule.storageIds.includes(action.storageId))) return false;
  if (rule.executables && (!action.executable || !rule.executables.some((item) => glob(item, action.executable ?? "")))) return false;
  if (rule.services && (!action.service || !rule.services.some((item) => glob(item, action.service ?? "")))) return false;
  if (rule.sourceNetworks && (!action.sourceIp || !rule.sourceNetworks.some((item) => inNetwork(action.sourceIp ?? "", item)))) return false;
  if (rule.timeWindows && !rule.timeWindows.some((window) => withinWindow(window))) return false;
  return true;
}

function protectedReference(action: PolicyAction, protectedTerms: string[]): boolean {
  const text = canonicalJson(action).toLowerCase();
  return protectedTerms.some((term) => text.includes(term.toLowerCase()));
}

function protectedMutation(action: PolicyAction, protectedTerms: string[]): boolean {
  if (!protectedReference(action, protectedTerms)) return false;
  if (["fs:read", "fs:list", "fs:stat", "api:get"].includes(action.action)) return false;
  if (action.action === "host:exec") {
    const base = (action.executable ?? "").split("/").pop() ?? "";
    return !READ_ONLY_EXECUTABLES.has(base);
  }
  return true;
}

function builtinDecision(profile: Principal["profile"], action: PolicyAction): PolicyDecision {
  if (profile === "root") return { effect: "allow", reason: "Root profile allows this action" };
  if (profile === "admin") {
    if (action.action.startsWith("api:") || action.action.startsWith("fs:") || action.action.startsWith("service:") || action.action === "audit:read") return { effect: "allow", reason: "Admin profile allows API, filesystem, and service administration" };
    return { effect: "deny", reason: "Admin profile does not allow host command or key administration" };
  }
  if (profile === "operator") {
    if (["api:get", "task:read", "schema:read", "fs:read", "fs:list", "fs:stat", "service:status"].includes(action.action)) return { effect: "allow", reason: "Operator profile allows read operations" };
    if (action.action === "api:post" && /\/status\/(?:start|stop|shutdown|reboot|reset|suspend|resume)$/.test(action.resource)) return { effect: "allow", reason: "Operator profile allows guest power actions" };
    return { effect: "deny", reason: "Operator profile does not allow this mutation" };
  }
  if (["api:get", "task:read", "schema:read", "fs:read", "fs:list", "fs:stat", "service:status"].includes(action.action)) return { effect: "allow", reason: "Read-only profile allows this action" };
  return { effect: "deny", reason: "Read-only profile blocks mutations" };
}

export class PolicyStore {
  constructor(private readonly filename: string, private readonly protectedTerms: string[]) {}
  private async load(): Promise<PolicyDatabase> { return readJson<PolicyDatabase>(this.filename, { version: 1, policies: [], drafts: [] }); }
  private async save(database: PolicyDatabase): Promise<void> { await atomicWriteJson(this.filename, database, 0o640); }

  async evaluate(principal: Principal, action: PolicyAction): Promise<PolicyDecision> {
    if (protectedMutation(action, this.protectedTerms)) return { effect: "breakglass", reason: "The action may modify the protected model repository and requires two-stage break-glass approval" };
    if (principal.profile !== "custom") return builtinDecision(principal.profile, action);
    if (!principal.policyId) return { effect: "deny", reason: "Custom key has no policy binding" };
    const database = await this.load(); const policy = database.policies.find((item) => item.id === principal.policyId && item.active);
    if (!policy) return { effect: "deny", reason: "The bound custom policy is missing or inactive" };
    const decisions = policy.rules.filter((rule) => ruleMatches(rule, action));
    if (decisions.length === 0) return { effect: policy.defaultEffect, reason: `Policy default is ${policy.defaultEffect}` };
    const selected = decisions.sort((left, right) => EFFECT_RANK[right.effect] - EFFECT_RANK[left.effect])[0];
    if (!selected) return { effect: "deny", reason: "No policy rule matched" };
    return { effect: selected.effect, reason: selected.description ?? `Matched policy rule ${selected.id}`, ruleId: selected.id };
  }

  async draft(input: unknown): Promise<PolicyDraft> {
    const document = PolicyDocumentSchema.parse(input); const digest = sha256(canonicalJson(document));
    const selectors = new Map<string, PolicyEffect>(); const warnings: string[] = [];
    for (const rule of document.rules) {
      const selector = canonicalJson({ ...rule, id: undefined, effect: undefined, description: undefined });
      const existing = selectors.get(selector);
      if (existing && existing !== rule.effect) warnings.push(`Rule ${rule.id} conflicts with another rule using the same selectors; the more restrictive effect wins.`);
      selectors.set(selector, rule.effect);
    }
    const draft: PolicyDraft = { id: randomUUID(), document, digest, createdAt: new Date().toISOString(), warnings };
    const database = await this.load(); database.drafts.push(draft); await this.save(database); return draft;
  }

  async simulate(draftId: string, actions: PolicyAction[]): Promise<JsonValue> {
    const database = await this.load(); const draft = database.drafts.find((item) => item.id === draftId);
    if (!draft) throw new Error(`Policy draft '${draftId}' was not found`);
    const results = actions.map((action) => {
      if (protectedMutation(action, this.protectedTerms)) return { action, decision: { effect: "breakglass", reason: "Global model guard" } };
      const matches = draft.document.rules.filter((rule) => ruleMatches(rule, action));
      const selected = matches.sort((left, right) => EFFECT_RANK[right.effect] - EFFECT_RANK[left.effect])[0];
      return { action, decision: selected ? { effect: selected.effect, reason: selected.description ?? selected.id } : { effect: draft.document.defaultEffect, reason: "Policy default" } };
    });
    return { draftId, digest: draft.digest, results } as unknown as JsonValue;
  }

  async activate(draftId: string, confirmation: string): Promise<StoredPolicy> {
    const database = await this.load(); const draft = database.drafts.find((item) => item.id === draftId);
    if (!draft) throw new Error(`Policy draft '${draftId}' was not found`);
    const required = `ACTIVATE ${draft.digest.slice(0, 12)}`;
    if (confirmation !== required) throw new Error(`Confirmation must exactly equal '${required}'`);
    const version = Math.max(0, ...database.policies.filter((item) => item.name === draft.document.name).map((item) => item.version)) + 1;
    const policy: StoredPolicy = { ...draft.document, id: randomUUID(), version, digest: draft.digest, createdAt: new Date().toISOString(), active: true };
    database.policies.push(policy); database.drafts = database.drafts.filter((item) => item.id !== draftId); await this.save(database); return policy;
  }

  async list(): Promise<StoredPolicy[]> { return (await this.load()).policies; }
}
