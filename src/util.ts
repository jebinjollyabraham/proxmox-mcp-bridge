import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { JsonValue } from "./types.js";

export function canonicalize(value: unknown): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : String(value);
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, canonicalize(record[key])])) as JsonValue;
  }
  return String(value);
}

export function canonicalJson(value: unknown): string { return JSON.stringify(canonicalize(value)); }
export function sha256(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }

export async function readJson<T>(filename: string, fallback: T): Promise<T> {
  try { return JSON.parse(await readFile(filename, "utf8")) as T; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return fallback; throw error; }
}

export async function atomicWriteJson(filename: string, value: unknown, mode = 0o640): Promise<void> {
  await mkdir(path.dirname(filename), { recursive: true });
  const temporary = `${filename}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode });
  await rename(temporary, filename);
}

export function asJsonValue(value: unknown): JsonValue { return canonicalize(value); }

export function truncate(value: unknown, limit: number): JsonValue {
  const text = JSON.stringify(value);
  if (text.length <= limit) return asJsonValue(value);
  return { truncated: true, originalCharacters: text.length, preview: text.slice(0, Math.max(0, limit - 256)), message: "Response exceeded the configured character limit. Narrow the query or use pagination." };
}

export function errorMessage(error: unknown): string { return error instanceof Error ? error.message : String(error); }
export function sleep(milliseconds: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }
