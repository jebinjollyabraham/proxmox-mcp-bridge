import test from "node:test";
import assert from "node:assert/strict";
import { parseApiSchema, SchemaRegistry } from "../schema.js";
const fixture = `const apiSchema = [{"path":"/nodes/{node}/status","info":{"GET":{"method":"GET","name":"status","description":"Read status","allowtoken":1,"parameters":{"type":"object"},"returns":{"type":"object"}},"POST":{"method":"POST","name":"change","description":"Reset state","allowtoken":0,"parameters":{"type":"object"},"returns":{"type":"string"}}}}];\nExt.onReady(() => {});`;
test("parses only the official schema assignment", () => {
  const snapshot = parseApiSchema(fixture); assert.equal(snapshot.endpointCount, 2); assert.equal(snapshot.endpoints[0]?.risk, "read"); assert.equal(snapshot.endpoints[1]?.risk, "destructive"); assert.equal(snapshot.endpoints[1]?.allowToken, false);
});
test("generates unique deterministic expanded tool names", () => {
  const snapshot = parseApiSchema(fixture); const names = snapshot.endpoints.map((endpoint) => endpoint.toolName); assert.equal(new Set(names).size, names.length);
  const registry = new SchemaRegistry(snapshot); assert.equal(registry.get("GET", "/nodes/{node}/status")?.name, "status");
});
