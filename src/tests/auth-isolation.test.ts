import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { KeyStore } from "../auth.js";

test("key expiry, revocation, and identities remain isolated", async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "pmcp-auth-isolation-")); context.after(async () => rm(directory, { recursive: true, force: true }));
  const keys = new KeyStore(path.join(directory, "keys.json")); const alice = await keys.create("alice", "read-only"); const bob = await keys.create("bob", "operator");
  const expired = await keys.create("expired", "admin", undefined, "2000-01-01T00:00:00.000Z");
  assert.equal((await keys.verify(alice.secret))?.name, "alice"); assert.equal((await keys.verify(bob.secret))?.name, "bob"); assert.equal(await keys.verify(expired.secret), null);
  await keys.revoke(alice.record.id); assert.equal(await keys.verify(alice.secret), null); assert.equal((await keys.verify(bob.secret))?.profile, "operator");
});
