# Security model

An MCP key with the `root` profile is intentionally powerful. Treat it like a root SSH credential: store it in a secret manager or OS keychain, never put it in source control, and create narrower per-person keys for normal use.

The HTTP process is unprivileged. Privileged actions cross a group-restricted Unix socket to a root helper. The helper validates action shapes and direct protected-path references independently. Its systemd namespace mounts `/mnt/model-repo` read-only and hides the known model LV device paths. A separate signed one-shot service handles only approved structured break-glass operations.

Every generic host command runs in a separate transient systemd sandbox with private PID and device namespaces, dropped mount/raw-device capabilities, a read-only model mount, and inaccessible bridge credentials, helper socket, Proxmox private keys, local `pvesh`, and systemd control sockets. Generic commands therefore cannot reconnect to the privileged helper, recover its API token, remount the model repository, invoke local Proxmox root APIs, or stop the bridge guard units. Structured service controls also reject changes to the bridge's own units.

These controls materially isolate model storage while retaining normal root file and executable behavior elsewhere. Root keys remain high-impact credentials and should not be given to untrusted agents. Prefer custom policies and executable allowlists.

HTTP keys are salted with scrypt and only the hash is retained. Audit records contain identities and operation digests, not API secrets or command output. The Proxmox service token remains on the host and is never returned through MCP.
