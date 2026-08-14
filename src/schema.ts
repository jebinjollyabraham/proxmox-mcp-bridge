import { readFile } from "node:fs/promises";
import type { ApiEndpoint, HttpMethod, JsonObject, JsonValue, RiskLevel, SchemaSnapshot } from "./types.js";
import { asJsonValue, atomicWriteJson, errorMessage, readJson, sha256 } from "./util.js";

const METHODS = new Set<HttpMethod>(["GET", "POST", "PUT", "DELETE"]);

function extractSchemaArray(source: string): unknown[] {
  const markerIndex = source.indexOf("const apiSchema");
  if (markerIndex < 0) throw new Error("Official API schema marker was not found");
  const start = source.indexOf("[", markerIndex);
  if (start < 0) throw new Error("Official API schema array was not found");
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = start; index < source.length; index += 1) {
    const character = source[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') inString = true;
    else if (character === "[") depth += 1;
    else if (character === "]") {
      depth -= 1;
      if (depth === 0) {
        const parsed = JSON.parse(source.slice(start, index + 1)) as unknown;
        if (!Array.isArray(parsed)) throw new Error("Official API schema root is not an array");
        return parsed;
      }
    }
  }
  throw new Error("Official API schema array is incomplete");
}

function riskFor(method: HttpMethod, path: string, description: string): RiskLevel {
  if (method === "GET") return "read";
  if (method === "DELETE") return "destructive";
  return /(?:destroy|delete|remove|erase|wipe|format|rollback|reset|purge|unlink)/.test(`${path} ${description}`.toLowerCase()) ? "destructive" : "write";
}

function baseToolName(method: HttpMethod, apiPath: string): string {
  const normalized = apiPath.replace(/[{}]/g, "").replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "").toLowerCase();
  const raw = `proxmox_${method.toLowerCase()}_${normalized || "root"}`;
  return raw.length <= 88 ? raw : `${raw.slice(0, 79)}_${sha256(raw).slice(0, 8)}`;
}

function normalize(tree: unknown[]): ApiEndpoint[] {
  const endpoints: ApiEndpoint[] = [];
  const names = new Map<string, string>();
  function visit(value: unknown): void {
    if (Array.isArray(value)) { for (const child of value) visit(child); return; }
    if (!value || typeof value !== "object") return;
    const node = value as Record<string, unknown>;
    if (typeof node.path === "string" && node.info && typeof node.info === "object") {
      for (const [methodName, rawInfo] of Object.entries(node.info as Record<string, unknown>)) {
        if (!METHODS.has(methodName as HttpMethod) || !rawInfo || typeof rawInfo !== "object") continue;
        const method = methodName as HttpMethod;
        const info = rawInfo as Record<string, unknown>;
        const description = typeof info.description === "string" ? info.description : "";
        const identity = `${method} ${node.path}`;
        let toolName = baseToolName(method, node.path);
        const previous = names.get(toolName);
        if (previous && previous !== identity) toolName = `${toolName.slice(0, 86)}_${sha256(identity).slice(0, 8)}`;
        names.set(toolName, identity);
        endpoints.push({
          method,
          path: node.path,
          name: typeof info.name === "string" ? info.name : method.toLowerCase(),
          description,
          parameters: asJsonValue(info.parameters ?? {}) as JsonObject,
          returns: asJsonValue(info.returns ?? null),
          permissions: asJsonValue(info.permissions ?? null),
          allowToken: info.allowtoken !== 0,
          risk: riskFor(method, node.path, description),
          toolName
        });
      }
    }
    if (node.children) visit(node.children);
  }
  visit(tree);
  return endpoints.sort((left, right) => `${left.path}:${left.method}`.localeCompare(`${right.path}:${right.method}`));
}

export function parseApiSchema(source: string, sourceName = "memory"): SchemaSnapshot {
  const endpoints = normalize(extractSchemaArray(source));
  if (endpoints.length === 0) throw new Error("Official API schema contained no methods");
  return { source: sourceName, sha256: sha256(source), loadedAt: new Date().toISOString(), endpointCount: endpoints.length, endpoints };
}

export class SchemaRegistry {
  readonly snapshot: SchemaSnapshot;
  private readonly byIdentity: Map<string, ApiEndpoint>;
  constructor(snapshot: SchemaSnapshot) {
    this.snapshot = snapshot;
    this.byIdentity = new Map(snapshot.endpoints.map((endpoint) => [`${endpoint.method} ${endpoint.path}`, endpoint]));
  }
  static async load(sourceFile: string, cacheFile: string): Promise<SchemaRegistry> {
    try {
      const source = await readFile(sourceFile, "utf8");
      const snapshot = parseApiSchema(source, sourceFile);
      await atomicWriteJson(cacheFile, snapshot);
      return new SchemaRegistry(snapshot);
    } catch (error) {
      const cached = await readJson<SchemaSnapshot | null>(cacheFile, null);
      if (!cached) throw error;
      return new SchemaRegistry({ ...cached, lastError: errorMessage(error) });
    }
  }
  get(method: HttpMethod, apiPath: string): ApiEndpoint | undefined { return this.byIdentity.get(`${method} ${apiPath}`); }
  search(query: string, method: HttpMethod | undefined, risk: RiskLevel | undefined, offset: number, limit: number): JsonValue {
    const needle = query.toLowerCase();
    const matches = this.snapshot.endpoints.filter((endpoint) => {
      if (method && endpoint.method !== method) return false;
      if (risk && endpoint.risk !== risk) return false;
      return !needle || `${endpoint.path} ${endpoint.name} ${endpoint.description} ${endpoint.method}`.toLowerCase().includes(needle);
    });
    const items = matches.slice(offset, offset + limit);
    return { total: matches.length, count: items.length, offset, hasMore: offset + items.length < matches.length, nextOffset: offset + items.length < matches.length ? offset + items.length : null, items: items.map(({ parameters: _parameters, returns: _returns, permissions: _permissions, ...endpoint }) => endpoint) as unknown as JsonValue };
  }
}
