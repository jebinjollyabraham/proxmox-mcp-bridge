import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { KeyStore } from "../auth.js";

test("key rotation revokes the old secret and exposes no stored hash", async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "pmcp-rotation-"));
  context.after(async () => rm(directory, { recursive: true, force: true }));
  const keys = new KeyStore(path.join(directory, "keys.json"));
  const first = await keys.create("alice", "operator");
  const rotated = await keys.rotate(first.record.id);

  assert.equal(await keys.verify(first.secret), null);
  assert.equal((await keys.verify(rotated.secret))?.name, "alice");
  assert.equal(rotated.replacedKeyId, first.record.id);
  assert.equal("salt" in rotated.record, false);
  assert.equal("hash" in rotated.record, false);
  assert.equal("salt" in (await keys.list())[0]!, false);
});
