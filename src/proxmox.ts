import https from "node:https";
import { readFile } from "node:fs/promises";
import type { ApiEndpoint, HttpMethod, JsonObject, JsonValue } from "./types.js";
import { asJsonValue, errorMessage } from "./util.js";
import { callHelper } from "./helper-client.js";

export interface ProxmoxClientOptions { baseUrl: string; tokenId?: string; tokenSecret?: string; caFile: string; tlsServername: string; helperSocket: string }
function scalar(value: JsonValue): string { return value !== null && typeof value === "object" ? JSON.stringify(value) : String(value); }
function fillPath(template: string, pathParams: Record<string, string>): string {
  return template.replace(/\{([^}]+)\}/g, (_match, name: string) => { const value = pathParams[name]; if (!value) throw new Error(`Missing required path parameter '${name}'`); return encodeURIComponent(value); });
}

export class ProxmoxClient {
  constructor(private readonly options: ProxmoxClientOptions) {}
  async invoke(endpoint: ApiEndpoint, pathParams: Record<string, string>, params: JsonObject, rootFallback: boolean): Promise<JsonValue> {
    const concretePath = fillPath(endpoint.path, pathParams);
    if (!endpoint.allowToken || !this.options.tokenId || !this.options.tokenSecret) {
      if (!rootFallback) throw new Error("This endpoint does not permit API tokens and the current policy does not allow local pvesh fallback"); return this.invokePvesh(endpoint.method, concretePath, params);
    }
    try { return await this.invokeHttp(endpoint.method, concretePath, params); }
    catch (error) { if (rootFallback && /returned (?:401|403)\b/i.test(errorMessage(error))) return this.invokePvesh(endpoint.method, concretePath, params); throw error; }
  }
  private async invokePvesh(method: HttpMethod, apiPath: string, params: JsonObject): Promise<JsonValue> {
    const result = await callHelper(this.options.helperSocket, "pvesh", { method, path: apiPath, params }, 120000);
    if (result && typeof result === "object" && !Array.isArray(result)) {
      const record = result as JsonObject; if (record.exitCode !== 0) throw new Error(`pvesh failed: ${String(record.stderr ?? "unknown error")}`);
      const stdout = String(record.stdout ?? "").trim(); return stdout ? asJsonValue(JSON.parse(stdout)) : null;
    }
    return result;
  }
  private async invokeHttp(method: HttpMethod, apiPath: string, params: JsonObject): Promise<JsonValue> {
    const base = new URL(this.options.baseUrl.endsWith("/") ? this.options.baseUrl : `${this.options.baseUrl}/`); const url = new URL(apiPath.replace(/^\//, ""), base);
    const form = new URLSearchParams(); for (const [key, value] of Object.entries(params)) form.set(key, scalar(value)); if (method === "GET") url.search = form.toString();
    const body = method === "GET" ? undefined : form.toString(); const ca = await readFile(this.options.caFile);
    return new Promise<JsonValue>((resolve, reject) => {
      const request = https.request(url, {
        method, ca, servername: this.options.tlsServername, rejectUnauthorized: true, timeout: 120000,
        headers: { Accept: "application/json", Authorization: `PVEAPIToken=${this.options.tokenId}=${this.options.tokenSecret}`, ...(body ? { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(body) } : {}) }
      }, (response) => {
        let responseBody = ""; response.setEncoding("utf8"); response.on("data", (chunk: string) => { responseBody += chunk; });
        response.on("end", () => {
          try {
            const parsed = responseBody ? JSON.parse(responseBody) as { data?: unknown; errors?: unknown } : {};
            if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) { reject(new Error(`Proxmox API ${method} ${apiPath} returned ${response.statusCode}: ${JSON.stringify(parsed.errors ?? parsed.data ?? responseBody).slice(0, 2000)}`)); return; }
            resolve(asJsonValue(parsed.data ?? null));
          } catch (error) { reject(error); }
        });
      });
      request.on("timeout", () => request.destroy(new Error("Proxmox API request timed out"))); request.on("error", reject); if (body) request.write(body); request.end();
    });
  }
}
