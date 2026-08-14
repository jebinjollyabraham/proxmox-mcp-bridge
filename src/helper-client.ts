import net from "node:net";
import { randomUUID } from "node:crypto";
import type { HelperRequest, HelperResponse, JsonObject, JsonValue } from "./types.js";

export async function callHelper(socketPath: string, action: HelperRequest["action"], params: JsonObject, timeoutMs = 30000): Promise<JsonValue> {
  const request: HelperRequest = { id: randomUUID(), action, params };
  return new Promise<JsonValue>((resolve, reject) => {
    const socket = net.createConnection(socketPath); let buffer = "";
    const timer = setTimeout(() => { socket.destroy(); reject(new Error(`Privileged helper timed out after ${timeoutMs}ms`)); }, timeoutMs + 1000);
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write(`${JSON.stringify(request)}\n`));
    socket.on("data", (chunk: string) => {
      buffer += chunk; const newline = buffer.indexOf("\n"); if (newline < 0) return;
      clearTimeout(timer); socket.end();
      try {
        const response = JSON.parse(buffer.slice(0, newline)) as HelperResponse;
        if (!response.ok) reject(new Error(response.error ?? "Privileged helper failed")); else resolve(response.result ?? null);
      } catch (error) { reject(error); }
    });
    socket.on("error", (error) => { clearTimeout(timer); reject(error); });
  });
}
