export interface SandboxedCommand {
  command: string;
  args: string[];
  timeoutMs: number;
}

export function buildSandboxedCommand(command: string, args: string[], cwd: string | undefined, timeoutMs: number): SandboxedCommand {
  const runtimeSeconds = Math.max(1, Math.ceil(timeoutMs / 1000));
  const systemdArgs = [
    "--quiet", "--wait", "--collect", "--pipe", "--service-type=exec",
    `--property=RuntimeMaxSec=${runtimeSeconds}s`,
    "--property=NoNewPrivileges=yes",
    "--property=PrivateDevices=yes",
    "--property=PrivateTmp=yes",
    "--property=PrivatePIDs=yes",
    "--property=ProtectProc=invisible",
    "--property=ProcSubset=pid",
    "--property=ProtectKernelTunables=yes",
    "--property=ProtectKernelModules=yes",
    "--property=ProtectControlGroups=yes",
    "--property=CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_RAWIO CAP_MKNOD CAP_SYS_MODULE CAP_SYS_PTRACE CAP_SYS_BOOT CAP_SYS_TIME",
    "--property=ReadOnlyPaths=-/mnt/model-repo",
    "--property=InaccessiblePaths=-/dev/pve/model-repo -/dev/mapper/pve-model--repo /run/proxmox-mcp-bridge /etc/proxmox-mcp-bridge /etc/pve/priv -/usr/bin/pvesh -/usr/sbin/pvesh /run/systemd/private /run/dbus/system_bus_socket",
    "--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "--setenv=LANG=C.UTF-8",
    ...(cwd ? [`--working-directory=${cwd}`] : []),
    "--", command, ...args
  ];
  return { command: "/usr/bin/systemd-run", args: systemdArgs, timeoutMs: timeoutMs + 5000 };
}
