#!/usr/bin/env node
import { createHmac } from "node:crypto";
import { chmod, mkdir, readFile, realpath, rm, stat, readdir, writeFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import { config } from "./config.js";
import type { HelperRequest, HelperResponse, JsonObject, JsonValue } from "./types.js";
import { asJsonValue, canonicalJson, errorMessage } from "./util.js";

const PROTECTED = [...config.protectedPaths, ...config.protectedIdentifiers].map((item) => item.toLowerCase());
const READ_ONLY_EXECUTABLES = new Set(["cat", "df", "du", "file", "find", "grep", "head", "ls", "rg", "sha256sum", "stat", "tail", "wc"]);
const NEVER_EXECUTE = new Set(["systemd-run"]);

function stringParam(params: JsonObject, key: string, required = true): string {
  const value = params[key]; if (typeof value === "string") return value; if (!required) return ""; throw new Error(`Helper parameter '${key}' must be a string`);
}
function numberParam(params: JsonObject, key: string, fallback: number): number {
  const value = params[key]; return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}
function containsProtected(value: unknown): boolean {
  const text = canonicalJson(value).toLowerCase(); return PROTECTED.some((term) => text.includes(term));
}
async function resolvedTarget(target: string): Promise<string> {
  const absolute = path.resolve(target);
  try { return await realpath(absolute); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    const parent = await realpath(path.dirname(absolute)); return path.join(parent, path.basename(absolute));
  }
}
async function assertWritableTarget(target: string): Promise<string> {
  const resolved = await resolvedTarget(target);
  if (containsProtected(resolved)) throw new Error("Protected model repository writes require the break-glass workflow");
  return resolved;
}
async function spawnCapture(command: string, args: string[], cwd: string | undefined, timeoutMs: number): Promise<JsonValue> {
  return new Promise<JsonValue>((resolve, reject) => {
    const child = spawn(command, args, { cwd, gid: 0, shell: false, env: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C.UTF-8" }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = ""; let stderr = ""; let truncated = false;
    const append = (current: string, chunk: Buffer): string => { const next = current + chunk.toString("utf8"); if (next.length <= config.responseCharacterLimit) return next; truncated = true; return next.slice(0, config.responseCharacterLimit); };
    child.stdout.on("data", (chunk: Buffer) => { stdout = append(stdout, chunk); });
    child.stderr.on("data", (chunk: Buffer) => { stderr = append(stderr, chunk); });
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.on("error", (error) => { clearTimeout(timer); reject(error); });
    child.on("close", (code, signal) => { clearTimeout(timer); resolve({ command, args, cwd: cwd ?? null, exitCode: code, signal, stdout, stderr, truncated }); });
  });
}
function objectParams(value: JsonValue | undefined): JsonObject {
  if (value && !Array.isArray(value) && typeof value === "object") return value as JsonObject; return {};
}

async function execute(request: HelperRequest): Promise<JsonValue> {
  const params = request.params;
  switch (request.action) {
    case "pvesh": {
      const method = stringParam(params, "method").toUpperCase(); const apiPath = stringParam(params, "path"); const apiParams = objectParams(params.params);
      if (method !== "GET" && containsProtected({ apiPath, apiParams })) throw new Error("Protected model API actions require break-glass approval");
      const command = ({ GET: "get", POST: "create", PUT: "set", DELETE: "delete" } as Record<string, string>)[method];
      if (!command) throw new Error(`Unsupported pvesh method '${method}'`);
      const args = [command, apiPath];
      for (const [key, value] of Object.entries(apiParams)) args.push(`--${key}`, typeof value === "object" ? JSON.stringify(value) : String(value));
      args.push("--output-format", "json"); return spawnCapture("/usr/bin/pvesh", args, undefined, numberParam(params, "timeoutMs", 120000));
    }
    case "exec": {
      const command = stringParam(params, "command"); const args = Array.isArray(params.args) ? params.args.map(String) : []; const base = path.basename(command);
      if (NEVER_EXECUTE.has(base)) throw new Error(`Execution of '${base}' is blocked by the helper`);
      if (containsProtected({ command, args }) && !READ_ONLY_EXECUTABLES.has(base)) throw new Error("Command may modify the protected model repository; use break-glass");
      const cwd = typeof params.cwd === "string" ? await resolvedTarget(params.cwd) : undefined;
      return spawnCapture(command, args, cwd, Math.min(numberParam(params, "timeoutMs", 30000), 900000));
    }
    case "fs_read": {
      const target = await resolvedTarget(stringParam(params, "path")); const encoding = params.encoding === "base64" ? null : "utf8";
      const content = await readFile(target, encoding); const rendered = Buffer.isBuffer(content) ? content.toString("base64") : content;
      return { path: target, encoding: encoding ? "utf8" : "base64", content: rendered.slice(0, config.responseCharacterLimit), truncated: rendered.length > config.responseCharacterLimit };
    }
    case "fs_write": {
      const target = await assertWritableTarget(stringParam(params, "path")); const content = stringParam(params, "content");
      const data = params.encoding === "base64" ? Buffer.from(content, "base64") : Buffer.from(content, "utf8");
      if (data.length > config.requestLimitBytes) throw new Error("File payload exceeds the configured request limit");
      await mkdir(path.dirname(target), { recursive: true }); await writeFile(target, data, { mode: Math.min(numberParam(params, "mode", 0o640), 0o777) });
      return { path: target, bytes: data.length };
    }
    case "fs_list": {
      const target = await resolvedTarget(stringParam(params, "path")); const entries = await readdir(target, { withFileTypes: true }); const limit = Math.min(numberParam(params, "limit", 100), 500);
      return { path: target, total: entries.length, entries: entries.slice(0, limit).map((entry) => ({ name: entry.name, type: entry.isDirectory() ? "directory" : entry.isFile() ? "file" : entry.isSymbolicLink() ? "symlink" : "other" })) };
    }
    case "fs_stat": {
      const target = await resolvedTarget(stringParam(params, "path")); const item = await stat(target);
      return { path: target, size: item.size, mode: item.mode, uid: item.uid, gid: item.gid, modifiedAt: item.mtime.toISOString(), type: item.isDirectory() ? "directory" : item.isFile() ? "file" : "other" };
    }
    case "service_status": {
      const service = stringParam(params, "service"); if (!/^[a-zA-Z0-9@_.:-]+$/.test(service)) throw new Error("Invalid systemd service name");
      return spawnCapture("/bin/systemctl", ["status", "--no-pager", "--", service], undefined, 15000);
    }
    case "service_control": {
      const service = stringParam(params, "service"); const action = stringParam(params, "action");
      if (!/^[a-zA-Z0-9@_.:-]+$/.test(service)) throw new Error("Invalid systemd service name");
      if (!["start", "stop", "restart", "reload", "enable", "disable"].includes(action)) throw new Error("Unsupported systemd service action");
      return spawnCapture("/bin/systemctl", [action, "--", service], undefined, 120000);
    }
    case "breakglass_submit": {
      const operation = objectParams(params.operation); const actionType = stringParam(operation, "type"); const target = stringParam(operation, "target");
      if (!containsProtected(target)) throw new Error("Break-glass is only valid for configured protected model targets");
      if (!["delete_file", "delete_directory", "delete_volume"].includes(actionType)) throw new Error("Unsupported break-glass action");
      const payload = { id: stringParam(params, "approvalId"), operation, expiresAt: stringParam(params, "expiresAt") };
      const secret = (await readFile(config.helperSecretFile, "utf8")).trim();
      const envelope = { payload, signature: createHmac("sha256", secret).update(canonicalJson(payload)).digest("hex") };
      await writeFile(config.breakglassRequest, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
      return { queued: true, approvalId: payload.id, resultFile: config.breakglassResult };
    }
  }
}

async function main(): Promise<void> {
  await mkdir(path.dirname(config.helperSocket), { recursive: true }); await rm(config.helperSocket, { force: true });
  const server = net.createServer((socket) => {
    socket.setEncoding("utf8"); let buffer = "";
    socket.on("data", (chunk: string) => {
      buffer += chunk; const newline = buffer.indexOf("\n"); if (newline < 0) return; const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1);
      void (async () => {
        let id = "unknown";
        try { const request = JSON.parse(line) as HelperRequest; id = request.id; const response: HelperResponse = { id, ok: true, result: asJsonValue(await execute(request)) }; socket.end(`${JSON.stringify(response)}\n`); }
        catch (error) { const response: HelperResponse = { id, ok: false, error: errorMessage(error) }; socket.end(`${JSON.stringify(response)}\n`); }
      })();
    });
  });
  server.listen(config.helperSocket, async () => { await chmod(config.helperSocket, 0o660); process.stderr.write(`Proxmox MCP privileged helper listening on ${config.helperSocket}\n`); });
}
main().catch((error) => { process.stderr.write(`${errorMessage(error)}\n`); process.exit(1); });
