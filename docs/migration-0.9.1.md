# Migrating To JStack v0.9.1

JStack v0.9.1 adds an Adaptive Context Gate to the existing five workflows.
There is no sixth slash command, staffing change, approval token, or terminal
step.

## User-visible behavior

- JStack inspects repository instructions, relevant files, configuration, and
  durable context before asking questions.
- Clear prompts continue without a questionnaire.
- Material ambiguity produces at most three questions per round. Every
  question explains why it matters and includes a recommended default.
- A user may answer normally or say to use the recommended defaults. Accepted
  low-risk defaults remain visible as assumptions.
- High-risk security, financial, legal, destructive, migration, and production
  material defaults require explicit confirmation in the conversation. That
  confirmation applies only to assumptions already shown and never accepts a
  new default batch at the same time.
- Audit defaults to the current subject, standard profile, all focus domains,
  and the ordinary failure threshold unless the request makes one of those
  materially ambiguous.
- Loop and Program use their existing stronger goal-readiness contracts, now
  with reasons and recommended defaults; the user is not asked twice.

## MCP integration

The canonical inventory increases from 49 to 50 tools with:

```text
jstack_context_readiness
```

Call it after inspection and before official planning:

```json
{
  "project_path": "/absolute/project",
  "goal": "Build me a 3D solar system",
  "workflow_mode": "jstack-subagents",
  "context": {
    "facts": [
      {
        "field": "platform",
        "value": "Existing browser application",
        "source_kind": "repository",
        "source_reference": "package.json"
      }
    ],
    "assumptions": [],
    "open_questions": []
  },
  "workflow_parameters": {}
}
```

A ready or defaulted result includes both `readinessReceipt` and
`normalizedBrief`. Pass them unchanged as `context_readiness_receipt` and
`context_brief` to `jstack_plan` and, for specialist modes,
`jstack_team_plan`. Audit passes the same pair to `jstack_audit` together with
the exact `context_goal`. For Audit, include every explicitly supplied
`profile`, `scope`, `focus`, and `base_ref` under `workflow_parameters`; changing
one invalidates the pair.

```json
{
  "goal": "Build me a 3D solar system",
  "team_mode": "smart-subagents",
  "context_readiness_receipt": "<readinessReceipt>",
  "context_brief": { "<exact>": "normalizedBrief" }
}
```

Direct MCP callers may omit the receipt for backward compatibility in 0.9.1,
but official JStack command workflows require it. Loop and Program callers
continue using `jstack_loop_goal_readiness` and
`jstack_program_goal_readiness`; do not add a duplicate shared-gate round.

## Receipt and privacy boundary

The receipt is session-local and short-lived. It binds goal and brief digests,
workflow, risk, project, evidence mode, tool version, and current Git state
when available. It contains no raw prompt, chat message, source content, user
answer, or secret. Restarting the MCP or changing the relevant repository state
requires a fresh gate call.

The separate normalized brief contains the bounded facts, assumptions, and
workflow parameters that the model already holds. Planning re-hashes it against
the receipt so assumptions remain visible and cannot be changed after intake.

The receipt is intake evidence only. It never authorizes implementation,
staffing escalation, Git publication, deployment, production mutation, or
release.

## Upgrade and verification

1. Install all five plugins and the shared MCP server from the same v0.9.1
   source or release tag.
2. Restart Codex.
3. Confirm `jstack_runtime_status` reports `0.9.1`.
4. Confirm `tools/list` contains 50 canonical tools and includes
   `jstack_context_readiness`.
5. Run `python3 ~/.codex/mcp/jstack/smoke_test.py` for a direct install.

Existing Loop/Program state and v0.9.0 evidence formats remain readable. A
v0.9.0 runtime cannot verify a v0.9.1 context-readiness receipt, and receipts do
not survive server restart by design.

## Rollback

Restore the complete v0.9.0 plugin and MCP unit, restart Codex, and rerun the
installed smoke test. Existing durable Loop/Program state does not require
deletion. Planning resumes without the shared receipt boundary until v0.9.1 is
reinstalled.
