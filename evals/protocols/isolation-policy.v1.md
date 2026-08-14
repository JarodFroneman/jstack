# Beta.1 isolated execution policy v1

This policy applies to every model attempt and grader invocation in the public
216-run study.

- The host Codex process runs ephemerally from an empty private directory. Its
  default shell, web search, apps, plugins, hooks, memories, project rules, and
  user configuration are disabled. Every condition receives one required local
  Proof MCP server exposing four allow-listed tools. Only the operational
  JStack condition additionally receives the exact registered 52-tool JStack
  MCP server, executed inside the same VM and bubblewrap boundary.
- Model credentials remain in the host keychain. They are never copied into a
  task image, workspace, environment variable, command, log, or evidence file.
- Each task runs in a fresh Apple `container` lightweight VM using an immutable
  OCI image digest, non-root uid/gid, dropped Linux capabilities, bounded CPU,
  memory, PIDs, time, output, tokens, cost, and tool calls.
- The OCI root filesystem is read-only. A single disposable task workspace and
  bounded tmpfs are writable. Host repositories, home directories, sockets,
  SSH agents, keychains, devices, and private state are not mounted.
- Each broker command receives an additional bubblewrap boundary that creates
  a new network, IPC, PID, and UTS namespace; rebinds the task root read-only;
  rebinds only `/workspace` writable; clears the environment; and provides a
  disposable `/tmp` and `/proc`.
- Dependency and source provisioning happens before attempts in a separately
  controlled builder. Model and grader execution are offline. No port or socket
  is published or forwarded.
- A canary must prove IPv4, IPv6, DNS, metadata, private-network, and host-network
  denial; non-root execution; empty capabilities; read-only root; bounded
  writable paths; absent host secrets; absent hidden tests; PID/resource limits;
  and teardown. Any failed or unverifiable canary blocks all model execution.
- Hidden tests and answer keys never enter a model VM. After all 216 model
  attempts are terminal, a separate sealed grading custodian applies each patch
  in a fresh grader VM and emits only closed counts and digests.
- One primary invocation exists per planned cell. A failed, blocked, or timed-out
  cell is retained. Diagnostic reruns are append-only operational evidence and
  never replace or rescore the planned attempt.
- Private raw prompts, source archives, workspaces, model JSONL, patches, command
  output, hidden tests, and reviewer identities stay in a mode-0700 local store.
  Public evidence contains minimized envelopes and digests only.
