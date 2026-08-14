import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { PolicyStore } from "../policy.js";
import type { Principal } from "../types.js";

test("built-in profiles enforce distinct read, power, service, and root capabilities", async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "pmcp-profile-")); context.after(async () => rm(directory, { recursive: true, force: true }));
  const store = new PolicyStore(path.join(directory, "policies.json"), ["model-repo"]); const principal = (profile: Principal["profile"]): Principal => ({ keyId: profile, name: profile, profile });
  const read = { action: "api:get", resource: "/nodes" }; const power = { action: "api:post", resource: "/nodes/infra/qemu/201/status/start" }; const service = { action: "service:control", resource: "pveproxy.service", service: "pveproxy.service" }; const exec = { action: "host:exec", resource: "/", executable: "/usr/bin/id" };
  for (const profile of ["read-only", "operator", "admin", "root"] as const) assert.equal((await store.evaluate(principal(profile), read)).effect, "allow");
  assert.equal((await store.evaluate(principal("read-only"), power)).effect, "deny"); assert.equal((await store.evaluate(principal("operator"), power)).effect, "allow");
  assert.equal((await store.evaluate(principal("operator"), service)).effect, "deny"); assert.equal((await store.evaluate(principal("admin"), service)).effect, "allow");
  assert.equal((await store.evaluate(principal("admin"), exec)).effect, "deny"); assert.equal((await store.evaluate(principal("root"), exec)).effect, "allow");
  assert.equal((await store.evaluate(principal("root"), { action: "fs:write", resource: "/mnt/model-repo/model.gguf" })).effect, "breakglass");
});

test("custom policies support future endpoints and constrained source/executable selectors", async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "pmcp-custom-selector-")); context.after(async () => rm(directory, { recursive: true, force: true }));
  const store = new PolicyStore(path.join(directory, "policies.json"), ["model-repo"]); const draft = await store.draft({ name: "future-reader", defaultEffect: "deny", sourceRules: "Allow current and future reads. Allow id only from tailnet.", rules: [
    { id: "future-api-read", effect: "allow", actions: ["api:get"], resources: ["**"] },
    { id: "tailnet-id", effect: "allow", actions: ["host:exec"], executables: ["/usr/bin/id"], sourceNetworks: ["100.64.0.0/10"] }
  ] }); const active = await store.activate(draft.id, `ACTIVATE ${draft.digest.slice(0, 12)}`); const principal: Principal = { keyId: "custom", name: "custom", profile: "custom", policyId: active.id };
  assert.equal((await store.evaluate(principal, { action: "api:get", resource: "/future/proxmox/endpoint" })).effect, "allow");
  assert.equal((await store.evaluate(principal, { action: "host:exec", resource: "/", executable: "/usr/bin/id", sourceIp: "100.104.4.10" })).effect, "allow");
  assert.equal((await store.evaluate(principal, { action: "host:exec", resource: "/", executable: "/usr/bin/id", sourceIp: "192.168.88.10" })).effect, "deny");
  assert.equal((await store.evaluate(principal, { action: "host:exec", resource: "/", executable: "/bin/sh", sourceIp: "100.104.4.10" })).effect, "deny");
});

test("unsupported conversational policy fields are rejected", async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "pmcp-unsupported-rule-")); context.after(async () => rm(directory, { recursive: true, force: true }));
  const store = new PolicyStore(path.join(directory, "policies.json"), ["model-repo"]);
  await assert.rejects(store.draft({ name: "unsupported", defaultEffect: "deny", sourceRules: "Trust my mood", rules: [], inferredMoodAccess: true }), /Unrecognized key/);
});
