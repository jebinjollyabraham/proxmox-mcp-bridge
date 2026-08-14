#!/usr/bin/env node
import { createHmac, timingSafeEqual } from "node:crypto";
import { readFile, rm, stat } from "node:fs/promises";
import { spawn } from "node:child_process";
import { config } from "./config.js";
import type { JsonObject } from "./types.js";
import { atomicWriteJson, canonicalJson, errorMessage, readJson } from "./util.js";

interface Envelope { payload: { id: string; operation: JsonObject; expiresAt: string }; signature: string }
function protectedTarget(target: string): boolean {
  const lowered = target.toLowerCase(); return [...config.protectedPaths, ...config.protectedIdentifiers].some((item) => lowered.includes(item.toLowerCase()));
}
async function run(command: string, args: string[]): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, { shell: false, stdio: ["ignore", "pipe", "pipe"] }); let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); }); child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve() : reject(new Error(`${command} failed with ${code}: ${stderr.slice(0, 1000)}`)));
  });
}
async function main(): Promise<void> {
  const envelope = JSON.parse(await readFile(config.breakglassRequest, "utf8")) as Envelope; const secret = (await readFile(config.helperSecretFile, "utf8")).trim();
  const expected = Buffer.from(createHmac("sha256", secret).update(canonicalJson(envelope.payload)).digest("hex"), "hex"); const actual = Buffer.from(envelope.signature, "hex");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error("Invalid break-glass request signature");
  if (Date.parse(envelope.payload.expiresAt) <= Date.now()) throw new Error("Break-glass approval expired");
  const used = await readJson<string[]>(config.breakglassUsedFile, []); if (used.includes(envelope.payload.id)) throw new Error("Break-glass approval has already been used");
  const operation = envelope.payload.operation; const type = String(operation.type ?? ""); const target = String(operation.target ?? "");
  if (!protectedTarget(target)) throw new Error("Break-glass target is outside configured model protection");
  if (type === "delete_file") { const item = await stat(target); if (!item.isFile()) throw new Error("Break-glass target is not a regular file"); await rm(target); }
  else if (type === "delete_directory") await rm(target, { recursive: true, force: false });
  else if (type === "delete_volume") { if (!["/dev/pve/model-repo", "/dev/mapper/pve-model--repo"].includes(target)) throw new Error("Volume is not the configured model LV"); await run("/usr/sbin/lvremove", ["--yes", target]); }
  else throw new Error(`Unsupported break-glass operation '${type}'`);
  used.push(envelope.payload.id); await atomicWriteJson(config.breakglassUsedFile, used, 0o600);
  await atomicWriteJson(config.breakglassResult, { approvalId: envelope.payload.id, success: true, completedAt: new Date().toISOString() }, 0o600); await rm(config.breakglassRequest, { force: true });
}
main().catch(async (error) => {
  await atomicWriteJson(config.breakglassResult, { success: false, error: errorMessage(error), completedAt: new Date().toISOString() }, 0o600).catch(() => undefined);
  await rm(config.breakglassRequest, { force: true }).catch(() => undefined); process.stderr.write(`${errorMessage(error)}\n`); process.exit(1);
});
