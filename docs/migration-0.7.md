# Migrating To JStack 0.7

> Historical guide: v0.8.2 removes the custom action-approval protocol
> described below. See [migration-0.8.2.md](migration-0.8.2.md).

JStack 0.7 adds a mandatory local-only default and exact one-time authorization
for repository, Git, release, deployment, and production actions. It upgrades
the existing five commands; it does not add a sixth command.

## Before Upgrade

1. Back up the installed MCP, plugins, Codex configuration, marketplace state,
   and `~/.jstack/` state.
2. Finish or intentionally stop active 0.6 loops and programs when practical.
   Their durable records remain readable, but 0.7 tool/policy binding can
   require a fresh revision or a new contract before mutation.
3. Record the current installed version and tool inventory.
4. Validate the 0.7 source checkout before installation.

## Behavioral Changes

- Every project is local-only by default.
- Repository creation, remote add, remote change, commit, push, pull-request
  creation, merge, tag creation, release creation, deployment, and production
  mutation are separate protected actions.
- A task request, broad verb, phase/remediation approval, audit pass,
  release-readiness result, specialist handoff, or loop/program completion
  receipt is never action authority.
- Each action needs a signed-local challenge, exact target, unchanged
  session/Git/policy/branch/remote state, fresh provider observation,
  destructive one-time consumption, and a permit valid for at most 60 seconds.
- A failed or retried operation requires a completely new authorization.
- Release readiness now reports `executionAuthorized=false` even when all
  evidence gates pass.

Local editing, review, testing, audit, artifact generation, and context work do
not require an external-action permit. JStack itself will not automatically
commit or publish the 0.7 upgrade during installation or migration.

## Identity Setup

External actions fail closed until a private identity configuration exists.
Copy `mcp/jstack/templates/jstack.external-action-identities.json` outside the
repository, replace the example identity and roles, set a private key
environment variable of at least 32 bytes, and set:

```text
JSTACK_EXTERNAL_ACTION_IDENTITY_CONFIG=/private/path/jstack.external-action-identities.json
```

Restart Codex so the MCP inherits the configuration. The human operator, not
Codex, runs `sign_external_action_authorization.py` with the returned encoded
payload and full challenge digest.

Existing program human-gate configuration remains separate under
`JSTACK_PROGRAM_IDENTITY_CONFIG`; 0.7 does not silently reuse one authority for
the other.

## Verify

Run the source suite, artifact synchronization check, and JSON-RPC smoke test.
After installation and restart, verify:

- `serverVersion` is `0.7.0`;
- `tools/list` exposes 50 canonical `jstack_*` tools;
- the three `jstack_external_action_*` tools are present;
- `jstack_runtime_status` reports `defaultMode=local-only`;
- a broad request such as "implement and deploy the phases" produces no
  authorization;
- a disposable test authorization rejects replay and target drift.

Do not test the boundary against a real repository, deployment, or production
system merely to prove it works. The automated suite uses disposable local
fixtures and performs no external operation.

## Rollback

Restore the 0.6 MCP, all five plugin versions, optional umbrella plugin, and
Codex configuration as one release unit, then restart Codex. Do not mix 0.6
skills with the 0.7 MCP or vice versa.

Preserve `~/.jstack/external-actions/` for forensic history or move it to a
private backup. Never reuse a 0.7 challenge, attestation, authorization receipt,
or permit after rollback; all are session- and version-bound and should be
treated as expired. Restore active loop/program work only from a known-good
backup and revalidate its contract under the selected version.
