import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PolicyStore } from "../policy.js";
test("root policy still requires break-glass for model writes", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "pmcp-policy-")); const store = new PolicyStore(path.join(directory, "policies.json"), ["/mnt/model-repo", "model-repo"]);
  const principal = { keyId: "root", name: "root", profile: "root" as const };
  assert.equal((await store.evaluate(principal, { action: "fs:read", resource: "/mnt/model-repo/model.gguf" })).effect, "allow");
  assert.equal((await store.evaluate(principal, { action: "fs:write", resource: "/mnt/model-repo/model.gguf" })).effect, "breakglass");
  assert.equal((await store.evaluate(principal, { action: "api:delete", resource: "/storage/model-repo/content", method: "DELETE" })).effect, "breakglass");
});
test("custom policy uses deny precedence and digest activation", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "pmcp-policy-")); const store = new PolicyStore(path.join(directory, "policies.json"), ["model-repo"]);
  const draft = await store.draft({ name: "vm-202-operator", defaultEffect: "deny", sourceRules: "Can read all APIs and start VM 202, but never delete anything.", rules: [
    { id: "read", effect: "allow", actions: ["api:get"] }, { id: "power", effect: "allow", actions: ["api:post"], resources: ["/nodes/*/qemu/202/status/start"] }, { id: "no-delete", effect: "deny", actions: ["api:delete"] }
  ] });
  const active = await store.activate(draft.id, `ACTIVATE ${draft.digest.slice(0, 12)}`); const principal = { keyId: "custom", name: "person", profile: "custom" as const, policyId: active.id };
  assert.equal((await store.evaluate(principal, { action: "api:get", resource: "/nodes" })).effect, "allow"); assert.equal((await store.evaluate(principal, { action: "api:delete", resource: "/nodes/infra/qemu/202" })).effect, "deny");
});
