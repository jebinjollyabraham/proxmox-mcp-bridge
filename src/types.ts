export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };
export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";
export type RiskLevel = "read" | "write" | "destructive";
export type BuiltinProfile = "read-only" | "operator" | "admin" | "root";
export type PolicyEffect = "allow" | "deny" | "confirm" | "breakglass";

export interface ApiEndpoint {
  method: HttpMethod;
  path: string;
  name: string;
  description: string;
  parameters: JsonObject;
  returns: JsonValue;
  permissions: JsonValue;
  allowToken: boolean;
  risk: RiskLevel;
  toolName: string;
}

export interface SchemaSnapshot {
  source: string;
  sha256: string;
  loadedAt: string;
  endpointCount: number;
  endpoints: ApiEndpoint[];
  lastError?: string;
}

export interface Principal {
  keyId: string;
  name: string;
  profile: BuiltinProfile | "custom";
  policyId?: string;
  sourceIp?: string;
}

export interface PolicyAction {
  action: string;
  resource: string;
  method?: HttpMethod;
  vmid?: number;
  storageId?: string;
  executable?: string;
  service?: string;
  sourceIp?: string;
  payload?: JsonValue;
}

export interface PolicyDecision {
  effect: PolicyEffect;
  reason: string;
  ruleId?: string;
}

export interface HelperRequest {
  id: string;
  action: "pvesh" | "exec" | "fs_read" | "fs_write" | "fs_list" | "fs_stat" | "service_status" | "service_control" | "breakglass_submit";
  params: JsonObject;
}

export interface HelperResponse {
  id: string;
  ok: boolean;
  result?: JsonValue;
  error?: string;
}
