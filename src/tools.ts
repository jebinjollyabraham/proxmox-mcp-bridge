import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { config } from "./config.js";
import type { ApiEndpoint, HelperRequest, HttpMethod, JsonObject, JsonValue, PolicyAction, Principal, RiskLevel } from "./types.js";
import { SchemaRegistry } from "./schema.js";
import { PolicyDocumentSchema, PolicyStore } from "./policy.js";
import { KeyStore } from "./auth.js";
import { AuditLog } from "./audit.js";
import { ProxmoxClient } from "./proxmox.js";
import { BreakglassStore, ConfirmationStore } from "./confirmations.js";
import { callHelper } from "./helper-client.js";
import { asJsonValue, errorMessage, sleep, truncate } from "./util.js";

export interface ServerDependencies {
  registry: SchemaRegistry; policies: PolicyStore; keys: KeyStore; audit: AuditLog; proxmox: ProxmoxClient; confirmations: ConfirmationStore; breakglass: BreakglassStore;
}

const MethodSchema = z.enum(["GET", "POST", "PUT", "DELETE"]);
const ParamsSchema = z.record(z.string(), z.unknown()).default({});
const PathParamsSchema = z.record(z.string(), z.string()).default({});
const ResultSchema = z.object({ result: z.unknown() });

function output(data: unknown) {
  const result = truncate(data, config.responseCharacterLimit);
  return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }], structuredContent: { result } };
}
function failure(error: unknown) { return { isError: true, content: [{ type: "text" as const, text: `Error: ${errorMessage(error)}` }] }; }

function endpointAction(principal: Principal, endpoint: ApiEndpoint, pathParams: Record<string, string>, params: JsonObject): PolicyAction {
  const resource = endpoint.path.replace(/\{([^}]+)\}/g, (_match, name: string) => pathParams[name] ?? `{${name}}`);
  const vmidValue = pathParams.vmid ? Number(pathParams.vmid) : undefined;
  const storageId = pathParams.storage ?? (typeof params.storage === "string" ? params.storage : undefined);
  return {
    action: `api:${endpoint.method.toLowerCase()}`, resource, method: endpoint.method,
    ...(Number.isInteger(vmidValue) ? { vmid: vmidValue as number } : {}), ...(storageId ? { storageId } : {}),
    ...(principal.sourceIp ? { sourceIp: principal.sourceIp } : {}), payload: params
  };
}
function requireRoot(principal: Principal): void { if (principal.profile !== "root") throw new Error("This administration tool requires a root-profile MCP key"); }

export function createProxmoxServer(principal: Principal, dependencies: ServerDependencies): McpServer {
  const { registry, policies, keys, audit, proxmox, confirmations, breakglass } = dependencies;
  const server = new McpServer({ name: "proxmox-mcp-server", version: "0.1.0" }, { instructions: "Search and describe the installed Proxmox schema before generic calls. Respect policy denials. Never attempt model-repository changes without explicit two-stage break-glass approval." });

  async function executeOperation(operation: JsonObject): Promise<JsonValue> {
    const type = String(operation.type ?? "");
    if (type === "api") {
      const method = String(operation.method) as HttpMethod; const apiPath = String(operation.path); const endpoint = registry.get(method, apiPath);
      if (!endpoint) throw new Error(`Unknown Proxmox endpoint '${method} ${apiPath}'. Use proxmox_api_search.`);
      return proxmox.invoke(endpoint, (operation.pathParams ?? {}) as Record<string, string>, (operation.params ?? {}) as JsonObject, principal.profile === "root");
    }
    if (type === "helper") return callHelper(config.helperSocket, String(operation.helperAction) as HelperRequest["action"], (operation.params ?? {}) as JsonObject, Number(operation.timeoutMs ?? 30000));
    throw new Error(`Unsupported pending operation '${type}'`);
  }

  async function authorized(action: PolicyAction, operation: JsonObject): Promise<JsonValue> {
    const started = Date.now(); const decision = await policies.evaluate(principal, action);
    if (decision.effect === "deny") {
      await audit.write({ principal, action: action.action, resource: action.resource, outcome: "denied", durationMs: Date.now() - started, details: asJsonValue(decision) });
      throw new Error(`Policy denied action: ${decision.reason}`);
    }
    if (decision.effect === "breakglass") {
      await audit.write({ principal, action: action.action, resource: action.resource, outcome: "denied", durationMs: Date.now() - started, details: asJsonValue(decision) });
      throw new Error(`Break-glass required: ${decision.reason}`);
    }
    if (decision.effect === "confirm") {
      const pending = await confirmations.create(principal.keyId, action, operation);
      await audit.write({ principal, action: action.action, resource: action.resource, outcome: "pending", durationMs: Date.now() - started });
      return { requiresConfirmation: true, confirmationId: pending.id, digest: pending.digest, expiresAt: pending.expiresAt, requiredPhrase: `EXECUTE ${pending.digest.slice(0, 12)}` };
    }
    try {
      const result = await executeOperation(operation);
      await audit.write({ principal, action: action.action, resource: action.resource, outcome: "allowed", durationMs: Date.now() - started }); return result;
    } catch (error) {
      await audit.write({ principal, action: action.action, resource: action.resource, outcome: "error", durationMs: Date.now() - started }); throw error;
    }
  }

  async function invoke(method: HttpMethod, apiPath: string, pathParams: Record<string, string>, params: JsonObject): Promise<JsonValue> {
    const endpoint = registry.get(method, apiPath);
    if (!endpoint) throw new Error(`Unknown Proxmox endpoint '${method} ${apiPath}'. Use proxmox_api_search to find the official template.`);
    return authorized(endpointAction(principal, endpoint, pathParams, params), { type: "api", method, path: apiPath, pathParams, params });
  }

  server.registerTool("proxmox_api_search", {
    title: "Search Proxmox API", description: "Search every locally installed official Proxmox API method by path, method, risk, name, or description. Read-only and paginated.",
    inputSchema: z.object({ query: z.string().default(""), method: MethodSchema.optional(), risk: z.enum(["read", "write", "destructive"]).optional(), offset: z.number().int().min(0).default(0), limit: z.number().int().min(1).max(100).default(25) }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, async ({ query, method, risk, offset, limit }) => { try { return output(registry.search(query, method as HttpMethod | undefined, risk as RiskLevel | undefined, offset, limit)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_api_describe", {
    title: "Describe Proxmox API Method", description: "Return the installed parameter schema, return schema, permissions, token support, and risk for one API method.",
    inputSchema: z.object({ method: MethodSchema, path: z.string().startsWith("/") }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, async ({ method, path }) => { try { const endpoint = registry.get(method, path); if (!endpoint) throw new Error(`Unknown endpoint '${method} ${path}'`); return output(endpoint); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_api_invoke", {
    title: "Invoke Proxmox API Method", description: "Invoke any installed API method after schema validation and per-key policy enforcement. Pass the official template path, separate path parameters, and API parameters.",
    inputSchema: z.object({ method: MethodSchema, path: z.string().startsWith("/"), path_params: PathParamsSchema, params: ParamsSchema }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ method, path, path_params, params }) => { try { return output(await invoke(method, path, path_params, asJsonValue(params) as JsonObject)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_schema_status", {
    title: "Get Proxmox Schema Status", description: "Report the official API schema source, hash, method count, load time, and refresh error.", inputSchema: z.object({}).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, async () => output({
    source: registry.snapshot.source,
    sha256: registry.snapshot.sha256,
    loadedAt: registry.snapshot.loadedAt,
    endpointCount: registry.snapshot.endpointCount,
    lastError: registry.snapshot.lastError ?? null
  }));

  server.registerTool("proxmox_action_confirm", {
    title: "Confirm Pending Proxmox Action", description: "Execute one policy-gated action after supplying the exact one-time confirmation phrase returned by its initial call.",
    inputSchema: z.object({ confirmation_id: z.string().uuid(), confirmation: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ confirmation_id, confirmation }) => { try { const pending = await confirmations.consume(confirmation_id, principal.keyId, confirmation); return output(await executeOperation(pending.operation)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_list_nodes", {
    title: "List Proxmox Nodes", description: "List nodes and current status.", inputSchema: z.object({}).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async () => { try { return output(await invoke("GET", "/nodes", {}, {})); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_cluster_status", {
    title: "Get Cluster Status", description: "Return cluster membership and node status.", inputSchema: z.object({}).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async () => { try { return output(await invoke("GET", "/cluster/status", {}, {})); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_list_guests", {
    title: "List VMs and Containers", description: "List QEMU VMs and LXC containers across the cluster.", inputSchema: z.object({}).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async () => { try { return output(await invoke("GET", "/cluster/resources", {}, { type: "vm" })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_list_storage", {
    title: "List Proxmox Storage", description: "List configured storage definitions.", inputSchema: z.object({}).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async () => { try { return output(await invoke("GET", "/storage", {}, {})); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_node_health", {
    title: "Get Node Health", description: "Return current CPU, memory, load, uptime, kernel, and boot status for one node.", inputSchema: z.object({ node: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ node }) => { try { return output(await invoke("GET", "/nodes/{node}/status", { node }, {})); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_node_disks", {
    title: "List Node Disks", description: "List physical disks known to a Proxmox node.", inputSchema: z.object({ node: z.string(), params: ParamsSchema }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ node, params }) => { try { return output(await invoke("GET", "/nodes/{node}/disks/list", { node }, asJsonValue(params) as JsonObject)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_node_network", {
    title: "List Node Network Configuration", description: "Return installed network interfaces and configuration for one node.", inputSchema: z.object({ node: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ node }) => { try { return output(await invoke("GET", "/nodes/{node}/network", { node }, {})); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_node_logs", {
    title: "Read Node Journal", description: "Read a bounded slice of the system journal through the official node API.", inputSchema: z.object({ node: z.string(), params: ParamsSchema }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ node, params }) => { try { return output(await invoke("GET", "/nodes/{node}/journal", { node }, asJsonValue(params) as JsonObject)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_node_updates", {
    title: "List Node Package Updates", description: "List available package updates for one node without installing them.", inputSchema: z.object({ node: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ node }) => { try { return output(await invoke("GET", "/nodes/{node}/apt/update", { node }, {})); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_guest_power", {
    title: "Control Guest Power", description: "Start, stop, shut down, reboot, reset, suspend, or resume a QEMU VM or LXC container through the official API.",
    inputSchema: z.object({ node: z.string(), type: z.enum(["qemu", "lxc"]), vmid: z.number().int().positive(), action: z.enum(["start", "stop", "shutdown", "reboot", "reset", "suspend", "resume"]), params: ParamsSchema }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ node, type, vmid, action, params }) => { try { return output(await invoke("POST", `/nodes/{node}/${type}/{vmid}/status/${action}`, { node, vmid: String(vmid) }, asJsonValue(params) as JsonObject)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_guest_get_config", {
    title: "Get Guest Configuration", description: "Read the installed configuration for a QEMU VM or LXC container.", inputSchema: z.object({ node: z.string(), type: z.enum(["qemu", "lxc"]), vmid: z.number().int().positive() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ node, type, vmid }) => { try { return output(await invoke("GET", `/nodes/{node}/${type}/{vmid}/config`, { node, vmid: String(vmid) }, {})); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_guest_update_config", {
    title: "Update Guest Configuration", description: "Update QEMU VM or LXC configuration through the installed official schema and policy engine.", inputSchema: z.object({ node: z.string(), type: z.enum(["qemu", "lxc"]), vmid: z.number().int().positive(), params: ParamsSchema }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true }
  }, async ({ node, type, vmid, params }) => { try { return output(await invoke("PUT", `/nodes/{node}/${type}/{vmid}/config`, { node, vmid: String(vmid) }, asJsonValue(params) as JsonObject)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_guest_snapshot_list", {
    title: "List Guest Snapshots", description: "List snapshots for a QEMU VM or LXC container.", inputSchema: z.object({ node: z.string(), type: z.enum(["qemu", "lxc"]), vmid: z.number().int().positive() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ node, type, vmid }) => { try { return output(await invoke("GET", `/nodes/{node}/${type}/{vmid}/snapshot`, { node, vmid: String(vmid) }, {})); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_guest_snapshot_create", {
    title: "Create Guest Snapshot", description: "Create a named snapshot for a QEMU VM or LXC container.", inputSchema: z.object({ node: z.string(), type: z.enum(["qemu", "lxc"]), vmid: z.number().int().positive(), snapname: z.string().min(1), params: ParamsSchema }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
  }, async ({ node, type, vmid, snapname, params }) => { try { return output(await invoke("POST", `/nodes/{node}/${type}/{vmid}/snapshot`, { node, vmid: String(vmid) }, { ...(asJsonValue(params) as JsonObject), snapname })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_guest_snapshot_delete", {
    title: "Delete Guest Snapshot", description: "Delete one named QEMU VM or LXC snapshot.", inputSchema: z.object({ node: z.string(), type: z.enum(["qemu", "lxc"]), vmid: z.number().int().positive(), snapname: z.string().min(1), params: ParamsSchema }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ node, type, vmid, snapname, params }) => { try { return output(await invoke("DELETE", `/nodes/{node}/${type}/{vmid}/snapshot/{snapname}`, { node, vmid: String(vmid), snapname }, asJsonValue(params) as JsonObject)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_guest_snapshot_rollback", {
    title: "Roll Back Guest Snapshot", description: "Roll a QEMU VM or LXC container back to one named snapshot.", inputSchema: z.object({ node: z.string(), type: z.enum(["qemu", "lxc"]), vmid: z.number().int().positive(), snapname: z.string().min(1), params: ParamsSchema }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ node, type, vmid, snapname, params }) => { try { return output(await invoke("POST", `/nodes/{node}/${type}/{vmid}/snapshot/{snapname}/rollback`, { node, vmid: String(vmid), snapname }, asJsonValue(params) as JsonObject)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_guest_backup", {
    title: "Back Up Guest", description: "Start a vzdump backup for one VM or container and return its UPID.", inputSchema: z.object({ node: z.string(), vmid: z.number().int().positive(), storage: z.string().optional(), mode: z.enum(["snapshot", "suspend", "stop"]).optional(), params: ParamsSchema }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
  }, async ({ node, vmid, storage, mode, params }) => { try { return output(await invoke("POST", "/nodes/{node}/vzdump", { node }, { ...(asJsonValue(params) as JsonObject), vmid, ...(storage ? { storage } : {}), ...(mode ? { mode } : {}) })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_guest_console_metadata", {
    title: "Create Guest Console Metadata", description: "Create short-lived VNC or SPICE proxy metadata for a QEMU VM or LXC container.", inputSchema: z.object({ node: z.string(), type: z.enum(["qemu", "lxc"]), vmid: z.number().int().positive(), protocol: z.enum(["vnc", "spice"]), params: ParamsSchema }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
  }, async ({ node, type, vmid, protocol, params }) => { try { return output(await invoke("POST", `/nodes/{node}/${type}/{vmid}/${protocol}proxy`, { node, vmid: String(vmid) }, asJsonValue(params) as JsonObject)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_task_get", {
    title: "Get Proxmox Task Status", description: "Get status for a Proxmox UPID task.", inputSchema: z.object({ node: z.string(), upid: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ node, upid }) => { try { return output(await invoke("GET", "/nodes/{node}/tasks/{upid}/status", { node, upid }, {})); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_task_wait", {
    title: "Wait for Proxmox Task", description: "Poll a UPID until it stops or the bounded timeout expires.",
    inputSchema: z.object({ node: z.string(), upid: z.string(), timeout_seconds: z.number().int().min(1).max(300).default(60), poll_seconds: z.number().int().min(1).max(10).default(2) }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ node, upid, timeout_seconds, poll_seconds }) => {
    try {
      const deadline = Date.now() + timeout_seconds * 1000; let status: JsonValue = null;
      do { status = await invoke("GET", "/nodes/{node}/tasks/{upid}/status", { node, upid }, {}); if (status && typeof status === "object" && !Array.isArray(status) && (status as JsonObject).status === "stopped") return output(status); await sleep(poll_seconds * 1000); } while (Date.now() < deadline);
      return output({ timedOut: true, status });
    } catch (error) { return failure(error); }
  });

  server.registerTool("proxmox_task_log", {
    title: "Read Proxmox Task Log", description: "Read a paginated UPID task log.", inputSchema: z.object({ node: z.string(), upid: z.string(), start: z.number().int().min(0).default(0), limit: z.number().int().min(1).max(1000).default(100) }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ node, upid, start, limit }) => { try { return output(await invoke("GET", "/nodes/{node}/tasks/{upid}/log", { node, upid }, { start, limit })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_task_cancel", {
    title: "Cancel Proxmox Task", description: "Request cancellation of one running UPID task after policy enforcement.", inputSchema: z.object({ node: z.string(), upid: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ node, upid }) => { try { return output(await invoke("DELETE", "/nodes/{node}/tasks/{upid}", { node, upid }, {})); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_host_exec", {
    title: "Execute Host Command", description: "Run one non-interactive executable with an argument array. No shell expansion is performed. Model paths remain protected.",
    inputSchema: z.object({ command: z.string().min(1), args: z.array(z.string()).max(200).default([]), cwd: z.string().optional(), timeout_ms: z.number().int().min(100).max(900000).default(30000) }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ command, args, cwd, timeout_ms }) => {
    try {
      const action: PolicyAction = { action: "host:exec", resource: cwd ?? "/", executable: command, ...(principal.sourceIp ? { sourceIp: principal.sourceIp } : {}), payload: { command, args, cwd: cwd ?? null } };
      return output(await authorized(action, { type: "helper", helperAction: "exec", params: { command, args, ...(cwd ? { cwd } : {}), timeoutMs: timeout_ms }, timeoutMs: timeout_ms }));
    } catch (error) { return failure(error); }
  });

  server.registerTool("proxmox_host_read_file", {
    title: "Read Host File", description: "Read a UTF-8 or base64 host file with response truncation.", inputSchema: z.object({ path: z.string(), encoding: z.enum(["utf8", "base64"]).default("utf8") }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async (params) => { try { const action: PolicyAction = { action: "fs:read", resource: params.path, ...(principal.sourceIp ? { sourceIp: principal.sourceIp } : {}) }; return output(await authorized(action, { type: "helper", helperAction: "fs_read", params: asJsonValue(params) as JsonObject })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_host_write_file", {
    title: "Write Host File", description: "Write a bounded UTF-8 or base64 host file. Protected model paths require break-glass.",
    inputSchema: z.object({ path: z.string(), content: z.string().max(config.requestLimitBytes * 2), encoding: z.enum(["utf8", "base64"]).default("utf8"), mode: z.number().int().min(0).max(0o777).default(0o640) }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true }
  }, async (params) => { try { const action: PolicyAction = { action: "fs:write", resource: params.path, ...(principal.sourceIp ? { sourceIp: principal.sourceIp } : {}), payload: asJsonValue(params) }; return output(await authorized(action, { type: "helper", helperAction: "fs_write", params: asJsonValue(params) as JsonObject })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_host_download", {
    title: "Download Host File", description: "Download a bounded host file as base64 for MCP transport.", inputSchema: z.object({ path: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ path }) => { try { const action: PolicyAction = { action: "fs:read", resource: path, ...(principal.sourceIp ? { sourceIp: principal.sourceIp } : {}) }; return output(await authorized(action, { type: "helper", helperAction: "fs_read", params: { path, encoding: "base64" } })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_host_upload", {
    title: "Upload Host File", description: "Upload a bounded base64 file. Protected model paths require break-glass.", inputSchema: z.object({ path: z.string(), content_base64: z.string().max(config.requestLimitBytes * 2), mode: z.number().int().min(0).max(0o777).default(0o640) }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true }
  }, async ({ path, content_base64, mode }) => { try { const params: JsonObject = { path, content: content_base64, encoding: "base64", mode }; const action: PolicyAction = { action: "fs:write", resource: path, ...(principal.sourceIp ? { sourceIp: principal.sourceIp } : {}), payload: params }; return output(await authorized(action, { type: "helper", helperAction: "fs_write", params })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_host_list_directory", {
    title: "List Host Directory", description: "List a host directory with a bounded result count.", inputSchema: z.object({ path: z.string(), limit: z.number().int().min(1).max(500).default(100) }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async (params) => { try { const action: PolicyAction = { action: "fs:list", resource: params.path, ...(principal.sourceIp ? { sourceIp: principal.sourceIp } : {}) }; return output(await authorized(action, { type: "helper", helperAction: "fs_list", params: asJsonValue(params) as JsonObject })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_host_stat", {
    title: "Stat Host Path", description: "Return type, ownership, mode, size, and modification time for a host path.", inputSchema: z.object({ path: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async (params) => { try { const action: PolicyAction = { action: "fs:stat", resource: params.path, ...(principal.sourceIp ? { sourceIp: principal.sourceIp } : {}) }; return output(await authorized(action, { type: "helper", helperAction: "fs_stat", params: asJsonValue(params) as JsonObject })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_service_status", {
    title: "Get Host Service Status", description: "Return systemd status for one service without changing it.", inputSchema: z.object({ service: z.string().regex(/^[a-zA-Z0-9@_.:-]+$/) }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }
  }, async ({ service }) => { try { const action: PolicyAction = { action: "service:status", resource: service, service, ...(principal.sourceIp ? { sourceIp: principal.sourceIp } : {}) }; return output(await authorized(action, { type: "helper", helperAction: "service_status", params: { service } })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_service_control", {
    title: "Control Host Service", description: "Start, stop, restart, reload, enable, or disable one validated systemd service after policy enforcement.", inputSchema: z.object({ service: z.string().regex(/^[a-zA-Z0-9@_.:-]+$/), action: z.enum(["start", "stop", "restart", "reload", "enable", "disable"]) }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ service, action }) => { try { const policyAction: PolicyAction = { action: "service:control", resource: service, service, ...(principal.sourceIp ? { sourceIp: principal.sourceIp } : {}), payload: { action } }; return output(await authorized(policyAction, { type: "helper", helperAction: "service_control", params: { service, action }, timeoutMs: 120000 })); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_policy_draft", {
    title: "Draft Custom Access Policy", description: "Validate and store a deterministic policy proposal translated from a person's onboarding rules. Root key required.", inputSchema: PolicyDocumentSchema, outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false }
  }, async (input) => { try { requireRoot(principal); return output(await policies.draft(input)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_policy_simulate", {
    title: "Simulate Policy Draft", description: "Evaluate representative actions against a policy draft before activation.",
    inputSchema: z.object({ draft_id: z.string().uuid(), actions: z.array(z.object({ action: z.string(), resource: z.string(), method: MethodSchema.optional(), vmid: z.number().int().positive().optional(), storageId: z.string().optional(), executable: z.string().optional(), service: z.string().optional() }).strict()).min(1).max(100) }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, async ({ draft_id, actions }) => { try { requireRoot(principal); return output(await policies.simulate(draft_id, actions as PolicyAction[])); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_policy_activate", {
    title: "Activate Policy Draft", description: "Activate an immutable policy version after exact digest confirmation. Root key required.", inputSchema: z.object({ draft_id: z.string().uuid(), confirmation: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false }
  }, async ({ draft_id, confirmation }) => { try { requireRoot(principal); return output(await policies.activate(draft_id, confirmation)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_policy_list", {
    title: "List Active Policies", description: "List deterministic policy versions. Root key required.", inputSchema: z.object({}).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, async () => { try { requireRoot(principal); return output(await policies.list()); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_key_create", {
    title: "Create MCP API Key", description: "Create a per-person key bound to a built-in profile or active custom policy. The secret is returned once. Root key required.",
    inputSchema: z.object({ name: z.string().min(1).max(120), profile: z.enum(["read-only", "operator", "admin", "root", "custom"]), policy_id: z.string().uuid().optional(), expires_at: z.iso.datetime().optional() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false }
  }, async ({ name, profile, policy_id, expires_at }) => { try { requireRoot(principal); return output(await keys.create(name, profile, policy_id, expires_at)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_key_list", {
    title: "List MCP API Keys", description: "List key metadata without key secrets. Root key required.", inputSchema: z.object({}).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, async () => { try { requireRoot(principal); return output(await keys.list()); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_key_rotate", {
    title: "Rotate MCP API Key", description: "Revoke one key and return its replacement secret exactly once. Root key required.", inputSchema: z.object({ id_or_name: z.string(), expires_at: z.iso.datetime().optional() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false }
  }, async ({ id_or_name, expires_at }) => { try { requireRoot(principal); return output(await keys.rotate(id_or_name, expires_at)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_key_revoke", {
    title: "Revoke MCP API Key", description: "Revoke a key by ID or name. Root key required.", inputSchema: z.object({ id_or_name: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false }
  }, async ({ id_or_name }) => { try { requireRoot(principal); return output(await keys.revoke(id_or_name)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_audit_tail", {
    title: "Read MCP Audit Trail", description: "Read recent redacted MCP audit records. Root key required.", inputSchema: z.object({ limit: z.number().int().min(1).max(500).default(50) }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, async ({ limit }) => { try { requireRoot(principal); return output(await audit.tail(limit)); } catch (error) { return failure(error); } });

  const BreakglassOperationSchema = z.object({ type: z.enum(["delete_file", "delete_directory", "delete_volume"]), target: z.string().min(1) }).strict();
  server.registerTool("proxmox_breakglass_prepare", {
    title: "Prepare Protected Model Action", description: "Prepare one exact model-destructive operation. Nothing is executed. Root key required.", inputSchema: z.object({ operation: BreakglassOperationSchema }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: true, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ operation }) => {
    try {
      requireRoot(principal); const serialized = JSON.stringify(operation).toLowerCase();
      if (![...config.protectedPaths, ...config.protectedIdentifiers].some((term) => serialized.includes(term.toLowerCase()))) throw new Error("Target is not a configured protected model resource");
      const approval = await breakglass.prepare(principal.keyId, asJsonValue(operation) as JsonObject); return output({ ...approval, requiredFirstPhrase: `CONFIRM 1 ${approval.digest.slice(0, 12)} ${approval.nonce1}` });
    } catch (error) { return failure(error); }
  });

  server.registerTool("proxmox_breakglass_confirm_first", {
    title: "First Model Action Confirmation", description: "Record the first exact confirmation for a protected model action.", inputSchema: z.object({ approval_id: z.string().uuid(), confirmation: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ approval_id, confirmation }) => { try { requireRoot(principal); const approval = await breakglass.confirmFirst(approval_id, principal.keyId, confirmation); return output({ ...approval, requiredSecondPhrase: `CONFIRM 2 ${approval.digest.slice(0, 12)} ${approval.nonce2}` }); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_breakglass_confirm_second", {
    title: "Second Model Action Confirmation", description: "Record the second independent confirmation for a protected model action.", inputSchema: z.object({ approval_id: z.string().uuid(), confirmation: z.string() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ approval_id, confirmation }) => { try { requireRoot(principal); return output(await breakglass.confirmSecond(approval_id, principal.keyId, confirmation)); } catch (error) { return failure(error); } });

  server.registerTool("proxmox_breakglass_execute", {
    title: "Execute Confirmed Model Action", description: "Execute exactly one protected model operation after both confirmations. Approval expires after one use or five minutes.", inputSchema: z.object({ approval_id: z.string().uuid() }).strict(), outputSchema: ResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
  }, async ({ approval_id }) => { try { requireRoot(principal); const approval = await breakglass.consume(approval_id, principal.keyId); return output(await callHelper(config.helperSocket, "breakglass_submit", { approvalId: approval.id, operation: approval.operation, expiresAt: approval.expiresAt })); } catch (error) { return failure(error); } });

  server.registerPrompt("proxmox_onboarding", {
    title: "Onboard a Proxmox MCP User", description: "Gather verbal access rules and compile them into a deterministic bridge policy.", argsSchema: z.object({ person_name: z.string(), requested_role: z.string().optional() }).strict()
  }, ({ person_name, requested_role }) => ({ messages: [{ role: "user", content: { type: "text", text: `Onboard ${person_name}${requested_role ? ` for ${requested_role}` : ""}. Ask what Proxmox APIs, VM IDs, storage, host paths, commands, services, source networks, schedules, and confirmations they need. Translate answers into proxmox_policy_draft. Never weaken the model guard. Simulate representative allowed and denied actions, show warnings and digest, obtain explicit approval, activate, then create a custom key. Report any verbal requirement that cannot be represented.` } }] }));

  if (config.toolMode === "expanded") {
    for (const endpoint of registry.snapshot.endpoints) {
      server.registerTool(endpoint.toolName, {
        title: `${endpoint.method} ${endpoint.path}`, description: `${endpoint.description || endpoint.name}\n\nOfficial endpoint: ${endpoint.method} ${endpoint.path}. Risk: ${endpoint.risk}. Use proxmox_api_describe for the complete installed schema.`,
        inputSchema: z.object({ path_params: PathParamsSchema, params: ParamsSchema }).strict(), outputSchema: ResultSchema,
        annotations: { readOnlyHint: endpoint.risk === "read", destructiveHint: endpoint.risk === "destructive", idempotentHint: endpoint.method === "GET" || endpoint.method === "PUT", openWorldHint: true }
      }, async ({ path_params, params }) => { try { return output(await invoke(endpoint.method, endpoint.path, path_params, asJsonValue(params) as JsonObject)); } catch (error) { return failure(error); } });
    }
  }
  return server;
}
