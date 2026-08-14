# Security model

An MCP key with the `root` profile is intentionally powerful. Treat it like a root SSH credential: store it in a secret manager or OS keychain, never put it in source control, and create narrower per-person keys for normal use.

The HTTP process is unprivileged. Privileged actions cross a group-restricted Unix socket to a root helper. The helper validates action shapes and direct protected-path references independently. Its systemd namespace mounts `/mnt/model-repo` read-only and hides the known model LV device paths. A separate signed one-shot service handles only approved structured break-glass operations.

These controls protect against ordinary mistakes and direct attempts. No software can promise that a deliberately hostile holder of genuinely general root execution is harmless. Do not give root keys to untrusted agents. Prefer custom policies and executable allowlists.

HTTP keys are salted with scrypt and only the hash is retained. Audit records contain identities and operation digests, not API secrets or command output. The Proxmox service token remains on the host and is never returned through MCP.
