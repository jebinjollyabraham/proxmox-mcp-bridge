#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { createProxmoxServer } from "./tools.js";
import { loadDependencies } from "./runtime.js";
import { errorMessage } from "./util.js";
async function main(): Promise<void> {
  const dependencies = await loadDependencies(); const server = createProxmoxServer({ keyId: "local-stdio", name: "Local stdio administrator", profile: "root", sourceIp: "local" }, dependencies);
  await server.connect(new StdioServerTransport());
}
main().catch((error) => { process.stderr.write(`${errorMessage(error)}\n`); process.exit(1); });
