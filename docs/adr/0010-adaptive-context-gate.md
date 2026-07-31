# ADR 0010: Adaptive Context Gate Across Existing Workflows

- Status: Accepted
- Date: 2026-07-31
- Target release: 0.9.1
- Extends: [ADR 0003](0003-goal-readiness-gate.md)

## Context

JStack's bounded Loop already prevents an underspecified semantic contract from
starting, but Dev, Subagents, Full Team, and Audit could move from a short user
prompt directly into planning. Models could silently choose the audience,
platform, constraints, acceptance bar, or operational boundary. A fixed
questionnaire would create the opposite failure: experienced users with clear
requests would be forced through repetitive intake, and agents might ask for
facts already present in the repository.

The desired behavior is adaptive. The agent must inspect first, ask only when
an answer could materially change the work, give the user a useful default,
and remain fail-closed when silent inference would be unsafe. It must preserve
the existing five commands and the host-native no-token action model.

## Decision

1. Add one read-only `jstack_context_readiness` MCP tool and
   `jstack.context-readiness.v1` output schema. Do not add a slash command or
   role.
2. Require the four non-Loop command workflows to inspect project instructions,
   relevant source, configuration, and durable context before calling the
   gate. Loop and Program use their stronger existing goal-readiness contracts
   as the same intake boundary.
3. Represent facts with one of five source kinds: `user`, `repository`,
   `policy`, `external-evidence`, or `inferred`. Keep assumptions separate.
4. Return `ready`, `proceed_with_assumptions`, `needs_context`, or
   `needs_confirmation`. Return at most three material questions per round;
   every question includes why it matters and a recommended default.
5. Permit accepted low-risk defaults as disclosed assumptions. Require explicit
   in-conversation confirmation before applying high/critical security,
   financial, legal, destructive, migration, or production material defaults.
6. Issue a short-lived session-local receipt only for a planning-ready state.
   Bind it to the normalized goal, brief digest, workflow, risk, project,
   evidence mode, tool version, and current Git HEAD/fingerprint when Git is
   available.
7. Store no raw prompts, messages, source content, user answers, or secrets in
   the receipt. A material goal, workflow, project, tool, or repository-state
   change invalidates it.
8. Bind official Dev, Subagents, Full Team, and Audit planning calls to the
   receipt plus the separately returned normalized brief. Verify its digest and
   keep facts and assumptions visible in planning. Audit additionally binds all
   explicitly supplied profile, scope, focus, and base selectors. Keep direct legacy MCP planning calls backward compatible during
   the minor release, while marking the context gate as required by official
   JStack workflows.
9. Extend Loop and Program question objects with reasons and recommended
   defaults. Reuse previously sourced answers and never run a duplicate general
   intake round.
10. Use normal conversation for answers and confirmation. Add no challenge,
    approval token, signer, mailbox, digest-paste request, or terminal command.

## Invariants

1. Repository-answerable questions are not sent to the user.
2. A clear prompt may produce zero questions.
3. No round contains more than three questions.
4. Assumptions remain visible to planning and handoff.
5. High-risk material gaps fail closed.
6. Audit remains read-only and uses safe default subject/profile behavior.
7. Context readiness does not authorize edits, staffing escalation, Git,
   deployment, production action, or release.
8. A receipt proves structured intake and binding, not the truth of every
   model-authored fact or the sufficiency of human judgment.

## Rejected Alternatives

- A sixth intake command: fragments the existing workflow and makes users learn
  another entry point.
- Ask questions before inspection: wastes user attention and encourages the
  model to ignore repository evidence.
- A mandatory fixed questionnaire: penalizes clear tasks and cannot adapt to
  domain risk.
- Unlimited clarification: creates interview loops without bounded progress.
- Silent defaults at high risk: can produce confidently verified work against
  the wrong safety or business contract.
- Reusing the retired approval-token protocol: context clarification is normal
  conversation, not an external-action authorization ceremony.
- Persisting raw conversation: unnecessary for binding and expands the privacy
  and secret-exposure surface.

## Consequences

Vague prompts may take one short clarification round before planning, while
specific prompts and ordinary audits proceed immediately. Official workflow
plans become traceable to a source-attributed brief and disclosed assumptions.
Receipts must be regenerated after MCP restart or relevant project drift.

The gate cannot guarantee that a user answer is correct, that repository
documentation is current, or that the model identified every material unknown.
QA, security, audit, launch assurance, release controls, and accountable human
review remain independent requirements.
