#!/usr/bin/env node
import http from "node:http";
import https from "node:https";
import { readFile } from "node:fs/promises";
import express, { type NextFunction, type Request, type Response } from "express";
import { createMcpExpressApp } from "@modelcontextprotocol/express";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import { config } from "./config.js";
import { createProxmoxServer } from "./tools.js";
import { loadDependencies } from "./runtime.js";
import { errorMessage } from "./util.js";

interface RateRecord { window: number; count: number }
function bearer(request: Request): string | null { const match = request.header("authorization")?.match(/^Bearer\s+(.+)$/i); return match?.[1] ?? null; }
function sourceIp(request: Request): string { return request.socket.remoteAddress?.replace(/^::ffff:/, "") ?? "unknown"; }

async function main(): Promise<void> {
  const dependencies = await loadDependencies();
  const app = createMcpExpressApp({ host: "0.0.0.0", allowedHosts: [...config.allowedHosts] });
  app.use(express.json({ limit: config.requestLimitBytes }));
  const rates = new Map<string, RateRecord>();
  app.use((request: Request, response: Response, next: NextFunction) => {
    const origin = request.header("origin");
    if (origin) {
      try { if (!config.allowedOrigins.includes(new URL(origin).hostname)) { response.status(403).json({ error: "Origin is not allowed" }); return; } }
      catch { response.status(403).json({ error: "Origin is invalid" }); return; }
    }
    next();
  });
  app.get("/healthz", (_request, response) => response.json({ status: "ok", schemaMethods: dependencies.registry.snapshot.endpointCount, schemaHash: dependencies.registry.snapshot.sha256, schemaError: dependencies.registry.snapshot.lastError ?? null }));

  const handler = async (request: Request, response: Response): Promise<void> => {
    const secret = bearer(request); if (!secret) { response.status(401).json({ error: "Authorization: Bearer <pmcp key> is required" }); return; }
    const principal = await dependencies.keys.verify(secret, sourceIp(request)); if (!principal) { response.status(401).json({ error: "API key is invalid, expired, or revoked" }); return; }
    const minute = Math.floor(Date.now() / 60000); const rateKey = `${principal.keyId}:${principal.sourceIp ?? "unknown"}`; const current = rates.get(rateKey);
    const record = current?.window === minute ? current : { window: minute, count: 0 }; record.count += 1; rates.set(rateKey, record);
    if (record.count > config.rateLimitPerMinute) { response.status(429).json({ error: "Per-key rate limit exceeded" }); return; }
    const server = createProxmoxServer(principal, dependencies); const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    response.on("close", () => { void transport.close(); }); await server.connect(transport); await transport.handleRequest(request, response, request.body);
  };
  app.post("/mcp", (request, response, next) => { void handler(request, response).catch(next); });
  app.post("/", (request, response, next) => { void handler(request, response).catch(next); });
  app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => { process.stderr.write(`HTTP error: ${errorMessage(error)}\n`); if (!response.headersSent) response.status(500).json({ error: "Internal MCP server error" }); });

  const httpServer = http.createServer(app); await new Promise<void>((resolve) => httpServer.listen(config.httpPort, config.httpHost, resolve));
  process.stderr.write(`Proxmox MCP HTTP listening on http://${config.httpHost}:${config.httpPort}/mcp\n`);
  let tlsServer: https.Server | undefined;
  try {
    const [cert, key] = await Promise.all([readFile(config.tlsCert), readFile(config.tlsKey)]); tlsServer = https.createServer({ cert, key }, app);
    await new Promise<void>((resolve) => tlsServer?.listen(config.lanPort, config.lanHost, resolve)); process.stderr.write(`Proxmox MCP LAN HTTPS listening on https://${config.lanHost}:${config.lanPort}/mcp\n`);
  } catch (error) { process.stderr.write(`LAN HTTPS disabled: ${errorMessage(error)}\n`); }
  const shutdown = (): void => { httpServer.close(); tlsServer?.close(); }; process.on("SIGTERM", shutdown); process.on("SIGINT", shutdown);
}
main().catch((error) => { process.stderr.write(`${errorMessage(error)}\n`); process.exit(1); });
