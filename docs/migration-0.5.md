# Migrating To JStack 0.5

> Historical guide: v0.8.2 replaces signed-local program gates with direct
> conversational decision records. See [migration-0.8.2.md](migration-0.8.2.md).

## Scope

Version 0.5 adds Program -> Phase orchestration and pause-aware child-loop
leases. Existing delivery, audit, and bounded-loop commands remain compatible.
No existing loop is automatically converted into a program.

## Before Upgrade

1. Finish or deliberately stop active write loops at a safe checkpoint.
2. Back up `~/.jstack`, `~/.codex/config.toml`, and the currently installed
   JStack plugin cache.
3. Confirm every project has a valid committed Git repository.
4. Run the current test and release checks for the existing installation.

The transactional installer stages all files and restores prior targets on a
late failure. Publishing or installing a release still requires explicit
release authorization.

## Policy Changes

Add the optional `program` section to repository policy:

```json
{
  "program": {
    "maxPhases": 100,
    "maxParallelPhases": 4,
    "maxActiveMinutes": 525600,
    "requireSignedApprovals": true,
    "requireCurrentEvidence": true,
    "requireFinalAudit": true,
    "allowedIdentityProviders": ["signed-local"]
  }
}
```

Repositories may lower numeric ceilings. Safety booleans and the identity
provider are enterprise floors in 0.5. Unknown or malformed fields fail policy
loading.

## Optional Human Approval Setup

Human gates require a private identity file and environment-held keys. Start
from `mcp/jstack/templates/jstack.program-identities.json`. Keep it outside
Git, set `JSTACK_PROGRAM_IDENTITY_CONFIG`, and give each approver key at least
32 bytes. Existing loops do not require this configuration.

## Existing Loop State

Pre-0.5 snapshots do not contain pause-aware active-time fields. The reader
derives a conservative elapsed value from existing timestamps and writes new
fields on the next lifecycle transition. Existing contract and event schemas
remain unchanged.

Approval waits now release a write-capable loop's checkout lease. Resuming an
old waiting loop reacquires the lease and fails if another active write loop
currently owns that checkout.

## New Program State

Program state is created only by `jstack_program_start` under
`~/.jstack/programs`. Every mutating program call requires an `operation_id`.
Persist the ID with the request and reuse it only for an exact retry.

Do not move an existing long loop into program state by copying files. Either
finish it, stop it and create a confirmed program from its remaining roadmap,
or keep it as a bounded loop if one acceptance boundary remains accurate.

## Rollback

Rolling the executable back to 0.4 leaves program state unread but does not
delete it. Stop active child loops first, restore the previous plugin/MCP and
config backup, and preserve `~/.jstack/programs` for a later 0.5 reinstall.
Pre-existing loop state remains readable by 0.4 so long as it was not revised
to depend on new pause semantics.

After reinstalling 0.5, run status before mutations; it validates the durable
event and snapshot chain.
