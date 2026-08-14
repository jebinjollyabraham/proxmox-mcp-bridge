import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseApiSchema, SchemaRegistry } from "../schema.js";
const fixture = `const apiSchema = [{"path":"/nodes/{node}/status","info":{"GET":{"method":"GET","name":"status","description":"Read status","allowtoken":1,"parameters":{"type":"object"},"returns":{"type":"object"}},"POST":{"method":"POST","name":"change","description":"Reset state","allowtoken":0,"parameters":{"type":"object"},"returns":{"type":"string"}}}}];\nExt.onReady(() => {});`;
const addedFixture = `const apiSchema = [{"path":"/nodes/{node}/status","info":{"GET":{"name":"status","allowtoken":1},"POST":{"name":"change","allowtoken":0}}},{"path":"/version","info":{"GET":{"name":"version","allowtoken":1}}}];`;
const removedFixture = `const apiSchema = [{"path":"/version","info":{"GET":{"name":"version","allowtoken":1}}}];`;
test("parses only the official schema assignment", () => {
  const snapshot = parseApiSchema(fixture); assert.equal(snapshot.endpointCount, 2); assert.equal(snapshot.endpoints[0]?.risk, "read"); assert.equal(snapshot.endpoints[1]?.risk, "destructive"); assert.equal(snapshot.endpoints[1]?.allowToken, false);
});
test("generates unique deterministic expanded tool names", () => {
  const snapshot = parseApiSchema(fixture); const names = snapshot.endpoints.map((endpoint) => endpoint.toolName); assert.equal(new Set(names).size, names.length);
  const registry = new SchemaRegistry(snapshot); assert.equal(registry.get("GET", "/nodes/{node}/status")?.name, "status");
});
test("realigns additions and removals while retaining last-known-good on malformed input", async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "pmcp-schema-")); context.after(async () => rm(directory, { recursive: true, force: true }));
  const source = path.join(directory, "apidoc.js"); const cache = path.join(directory, "registry.json");
  await writeFile(source, fixture); const initial = await SchemaRegistry.load(source, cache); assert.equal(initial.snapshot.endpointCount, 2);
  await writeFile(source, addedFixture); const added = await SchemaRegistry.load(source, cache); assert.equal(added.snapshot.endpointCount, 3); assert.notEqual(added.snapshot.sha256, initial.snapshot.sha256);
  await writeFile(source, removedFixture); const removed = await SchemaRegistry.load(source, cache); assert.equal(removed.snapshot.endpointCount, 1); assert.equal(removed.get("GET", "/nodes/{node}/status"), undefined);
  const lastKnownGood = await readFile(cache, "utf8"); await writeFile(source, "const apiSchema = ["); const fallback = await SchemaRegistry.load(source, cache);
  assert.equal(fallback.snapshot.endpointCount, 1); assert.match(fallback.snapshot.lastError ?? "", /incomplete/); assert.equal(await readFile(cache, "utf8"), lastKnownGood);
});
