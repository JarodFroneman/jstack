---
description: Run a read-only evidence-bound JStack repository audit
argument-hint: [SCOPE] [--profile quick|standard|deep|release] [OPTIONS]
---

Apply the JStack audit workflow to this repository.

Arguments:
$ARGUMENTS

Return usage without repository inspection for `help`, `--help`, or `?`.
Reject unsupported flags, invalid scopes, and invalid explicit base refs.

Defaults:

- scope: current Git delta for `quick`; repository root for other profiles
- profile: `standard`
- focus: `all`
- fail-on: `high`
- format: `markdown`
- learning-mode: `off`
- team-mode: `single-lead`

Supported options are `--profile`, `--focus`, `--base`, `--fail-on`,
`--format`, `--verify`, `--learning-mode`, and `--team-mode`.

This command is read-only. Do not edit code/configuration, change Git state,
install tools, write context, deploy, or access production. Remediation needs a
separate development task.

1. Read project instructions and relevant durable context.
2. Call `jstack_runtime_status` and `jstack_detect_project`.
3. Call `jstack_audit` to bind the profile, scope, repository state, policy,
   control digest, scope-manifest digest, adapters, review evidence, and
   existing `jstack_security_audit` evidence. Pass the parsed focus and apply
   the returned versioned `specialistCapabilityPlan`; selected capability
   domains may strengthen coverage but may never remove profile/policy domains.
4. Perform candidate generation and a separate challenge pass. Cite exact
   source locations and classify evidence honestly.
5. Execute no repository-controlled code by default. Quick never executes it.
   For other profiles, `--verify` permits only a curated adapter after exact
   approval and subject binding; offline flags are not an OS firewall.
6. Call `jstack_audit_finalize` with structured coverage, surviving findings,
   accepted-risk records, and requested output formats.
7. Report status, coverage, severity-ordered findings, blockers, residual risk,
   and next action. Never turn missing evidence into a pass.

If the requested audit team mode deploys platform specialists, obtain the
matching `jstack_team_plan`, keep every role read-only, validate each exact
role/capability result and metadata-only telemetry through
`jstack_specialist_result`, and require `jstack_specialist_handoff_check`
before Audit Lead synthesis. Store no raw prompts, messages, tool arguments,
command/model output, source contents, credentials, or secrets in telemetry.
The final audit receipt separately binds the capability catalog and selection
digests; specialist receipts never replace audit coverage/finding validation.

For artifact-only directories, report the aggregate scope-manifest digest and
limitations without a
Git-bound audit receipt or release-certification claim. Preserve the existing
`jstack_security_audit` contract and receipt as a separate security gate.

Use the installed `jstack-audit` skill. Use the normal Codex fallback only when
`jstack_runtime_status` itself is unavailable or unreachable.
