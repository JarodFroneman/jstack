# Adaptive Context Gate

JStack v0.9.1 adds one shared intake contract to the five existing workflows.
It does not add a command or role.

## Contract

1. Inspect the repository, its instructions, relevant durable context, and the
   current request before asking anything.
2. Separate facts by source: `user`, `repository`, `policy`,
   `external-evidence`, or `inferred`. Record assumptions separately.
3. Ask only questions whose answers could materially change scope,
   architecture, acceptance evidence, safety, or release behavior. Never ask a
   question the inspected project already answers.
4. Ask at most three questions in one round. Each question must state why it
   matters and include a recommended default. Normal conversation is the
   response channel; never ask for a token, digest, signer, or terminal paste.
5. If the user says to use recommended defaults, call the gate again with
   `use_recommended_defaults=true`. Low-risk work may continue with those
   assumptions disclosed. High/critical security, financial, legal,
   destructive, migration, or production gaps need explicit in-conversation
   confirmation and `confirm_material_inferences=true`. That confirmation call
   must carry only already displayed assumptions with
   `use_recommended_defaults=false`; it never applies the next question batch.
6. Do not repeat answered questions. Reuse the source-attributed facts and ask
   only newly material gaps. Re-run the gate after a material goal, workflow,
   project, or repository-state change.
7. Pass the returned `readinessReceipt` and matching `normalizedBrief` to
   `jstack_plan` and, when applicable, `jstack_team_plan` or `jstack_audit` as
   `context_readiness_receipt` and `context_brief`. The structured brief keeps
   facts and assumptions visible and is digest-verified. A stale or altered
   receipt/brief pair must be regenerated.
8. For audit, bind every explicitly supplied `profile`, `scope`, `focus`, and
   `base_ref` under `workflow_parameters` and pass the same selectors to
   `jstack_audit`. Changing one requires a fresh gate call.

## State Semantics

- `ready`: no material questions or assumptions remain.
- `proceed_with_assumptions`: planning may continue, but the assumptions must
  remain visible in the plan and handoff.
- `needs_context`: ask the returned questions and stop planning until answered
  or defaulted.
- `needs_confirmation`: high-risk defaults or material inferences need explicit
  confirmation before planning.

## Workflow Mapping

- `/j-stack-dev` -> `workflow_mode="j-stack-dev"`
- `/jstack-subagents` -> `workflow_mode="jstack-subagents"`
- `/jstack-full-team` -> `workflow_mode="jstack-full-team"`
- `/jstack-audit` -> `workflow_mode="jstack-audit"`; the ordinary request
  "audit this repository" uses safe defaults and normally asks nothing.
- `/jstack-loop` -> its existing `jstack_loop_goal_readiness` or
  `jstack_program_goal_readiness` is the stronger Adaptive Context Gate. Reuse
  answers from the shared intake rules and never run a duplicate question
  round.

Receipts contain structured digests and binding metadata only. The separate
normalized brief is returned to the model and remains visible in planning, but
is never embedded in the receipt. Receipts do not
store raw prompts, messages, source contents, secrets, or user answers.
