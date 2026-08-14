# Deterministic onboarding policies

The bridge does not pretend that an English sentence is an access-control mechanism. A connected harness transcribes the person's voice, asks clarifying questions, and submits a constrained policy document. The bridge validates, simulates, hashes, confirms, versions, and enforces that document.

## Precedence

1. The global model-repository guard always wins.
2. Among matching personal rules, `deny` wins over `breakglass`, `confirm`, and `allow`.
3. If no rule matches, `defaultEffect` is used. Custom policies should normally use `deny`.
4. Newly mapped API methods are denied unless a custom rule deliberately uses a wildcard that matches them.

## Example

```json
{
  "name": "vm-202-operator",
  "defaultEffect": "deny",
  "sourceRules": "May inspect everything and start or shut down VM 202 from the office or Tailnet. Never delete resources.",
  "rules": [
    { "id": "read-all", "effect": "allow", "actions": ["api:get"] },
    {
      "id": "power-202",
      "effect": "allow",
      "actions": ["api:post"],
      "resources": ["/nodes/*/qemu/202/status/start", "/nodes/*/qemu/202/status/shutdown"],
      "vmids": [202],
      "sourceNetworks": ["192.168.88.0/24", "100.64.0.0/10"]
    },
    { "id": "no-delete", "effect": "deny", "actions": ["api:delete", "fs:write"] }
  ]
}
```

Rules may filter action names, resource globs, HTTP methods, VM IDs, storage IDs, executables, systemd services, source IPv4 networks, and day/time windows. Requirements outside this vocabulary must be reported as unsupported during onboarding.
