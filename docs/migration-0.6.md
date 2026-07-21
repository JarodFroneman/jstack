# Migrating to JStack 0.6

JStack 0.6 upgrades the existing five commands with specialist capabilities;
it does not install a sixth command. The installer remains transactional, and
legacy `gstack_*` MCP aliases remain available.

## Before upgrading

1. Finish or record any active work and keep a recoverable copy of local JStack
   configuration.
2. Validate the checkout with `python3 scripts/sync_artifacts.py --check` and
   `python3 -m unittest discover -s tests -v`.
3. Review `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, and the specialist capability
   documentation.

## Install

Run the repository installer from the v0.6 checkout:

```bash
python3 scripts/install.py
```

For a non-default Codex home, pass `--codex-home PATH`. Restart Codex or open a
new task so the v0.6 MCP process and command skills are mounted together. Check
`jstack_runtime_status` before relying on the new fields.

## Client and workflow changes

- `jstack_plan` and `jstack_team_plan` now return a `capabilityPlan`, and agents
  include exact `capabilityIds`.
- Coordination packets must contain that actual plan. Dispatch callers that
  reconstruct or omit it will fail validation.
- Multi-agent workflows submit one `jstack_specialist_result` per planned role
  and validate the complete receipt set with
  `jstack_specialist_handoff_check` before synthesis.
- Raw free-form specialist prose can still be shown to the Lead, but it is not
  accepted as the machine-verifiable result. Use the published result and
  telemetry schemas.
- Audit callers may add `focus` or `capability_ids`; selected capability domains
  only strengthen required coverage.
- New loop contracts bind `capability_ids` through readiness, start, and
  material revision. Smart-subagent and full-team checkpoints/finalization
  require `specialist_handoff_receipt` evidence.

Omitting explicit capability IDs is supported and uses deterministic automatic
routing. Unknown or role-incompatible IDs fail closed.

## Existing state and receipts

Legacy loop state that predates `capabilityContract` remains readable. New or
materially revised loops use the v0.6 contract. Session-local QA, security,
audit, specialist, and readiness receipts do not survive an MCP restart and
must be regenerated against current project state.

## Rollback

Reinstall the prior tagged checkout with the same installer and restart Codex.
Do not copy individual v0.5 MCP or skill files over a v0.6 installation: mixed
server, catalog, schema, and command versions intentionally fail parity or
receipt checks. Preserve `~/.jstack` before any manual state migration.
