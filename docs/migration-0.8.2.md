# Migrating To JStack v0.8.2

JStack v0.8.2 removes all JStack-specific terminal approval and token flows.
This is a usability and trust-model change; the evidence, audit, launch,
release-readiness, loop, and program systems remain.

## Removed

- `jstack_external_action_challenge`
- `jstack_external_action_authorize`
- `jstack_external_action_consume`
- `jstack_program_gate_challenge`
- both approval signer scripts
- external-action authorization code and schemas
- external-action and program identity templates
- approval mailbox and HMAC environment configuration

The canonical MCP now exposes 49 `jstack_*` tools. Program orchestration exposes
13 `jstack_program_*` tools.

## Human Gates

Use `jstack_program_gate_resolve` after the named person explicitly approves or
rejects in the active conversation. Supply the approver ID, one role required
by the gate, decision, bounded non-secret reference, and operation ID. No
challenge or token is generated.

## Existing Policy Files

Remove these retired fields when convenient:

```text
externalActions
program.requireSignedApprovals
program.allowedIdentityProviders
```

The v0.8.2 loader ignores them and returns a migration warning, so an existing
v0.8.1 project does not fail during the first upgrade.

Remove retired MCP environment settings:

```text
JSTACK_EXTERNAL_ACTION_IDENTITY_CONFIG
JSTACK_EXTERNAL_ACTION_APPROVER_COMMAND
JSTACK_PROGRAM_IDENTITY_CONFIG
```

The current runtime never reads the old `~/.jstack/external-actions/` state.
Leave it in place if rollback is required, or remove it later using your normal
recoverable data-retention process.

## Upgrade

1. Back up the installed JStack MCP, plugin sources, Codex configuration, and
   `~/.jstack` state.
2. Install v0.8.2 with the transactional installer.
3. Restart Codex or open a new task.
4. Confirm `jstack_runtime_status` reports:
   - `serverVersion: 0.8.2`;
   - `actionSafety.mode: host-native`;
   - `customApprovalProtocol: false`;
   - `approvalTokenRequired: false`; and
   - `terminalApprovalRequired: false`.
5. Confirm `tools/list` contains 49 canonical tools and none of the four removed
   approval tools.

External actions now use the user's explicit request and ordinary Codex or
provider permissions. JStack Audit remains strictly read-only.
