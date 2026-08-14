import assert from "node:assert/strict";
import test from "node:test";
import { brotliCompressSync, deflateSync, gzipSync } from "node:zlib";
import { decodeProxmoxResponse } from "../proxmox.js";

test("decodes bounded compressed Proxmox API responses", () => {
  const json = JSON.stringify({ data: [{ node: "infra" }] }); const raw = Buffer.from(json);
  assert.equal(decodeProxmoxResponse(gzipSync(raw), "gzip"), json);
  assert.equal(decodeProxmoxResponse(deflateSync(raw), "deflate"), json);
  assert.equal(decodeProxmoxResponse(brotliCompressSync(raw), "br"), json);
  assert.equal(decodeProxmoxResponse(raw), json);
  assert.throws(() => decodeProxmoxResponse(raw, "identity", 4), /exceeds/);
  assert.throws(() => decodeProxmoxResponse(raw, "compress"), /Unsupported/);
});
