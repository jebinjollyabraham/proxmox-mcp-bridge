import assert from "node:assert/strict";
import test from "node:test";
import { buildSandboxedCommand } from "../command-sandbox.js";

test("generic root commands are wrapped in the immutable model sandbox", () => {
  const sandbox = buildSandboxedCommand("/bin/sh", ["-c", "id -u"], "/var/tmp", 1500); const separator = sandbox.args.indexOf("--");
  assert.equal(sandbox.command, "/usr/bin/systemd-run"); assert.equal(sandbox.timeoutMs, 6500); assert.ok(sandbox.args.includes("--property=RuntimeMaxSec=2s"));
  assert.ok(sandbox.args.includes("--property=PrivatePIDs=yes")); assert.ok(sandbox.args.includes("--property=ReadOnlyPaths=-/mnt/model-repo"));
  assert.ok(sandbox.args.some((item) => item.includes("/run/proxmox-mcp-bridge") && item.includes("/etc/pve/priv") && item.includes("/usr/bin/pvesh")));
  assert.ok(sandbox.args.some((item) => item.includes("CapabilityBoundingSet=~CAP_SYS_ADMIN"))); assert.equal(sandbox.args.find((item) => item.startsWith("--working-directory=")), "--working-directory=/var/tmp");
  assert.deepEqual(sandbox.args.slice(separator + 1), ["/bin/sh", "-c", "id -u"]);
});
