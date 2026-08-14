import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { KeyStore } from "../auth.js";
test("API keys are stored hashed and can be revoked", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "pmcp-auth-")); const store = new KeyStore(path.join(directory, "keys.json")); const created = await store.create("initial-root", "root");
  assert.match(created.secret, /^pmcp_/); assert.equal((await store.verify(created.secret))?.profile, "root"); const listed = await store.list(); assert.equal(Object.hasOwn(listed[0] ?? {}, "hash"), false);
  await store.revoke(created.record.id); assert.equal(await store.verify(created.secret), null);
});
