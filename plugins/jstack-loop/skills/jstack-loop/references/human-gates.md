# JStack Human Gates

## Purpose

Human gates represent accountable decisions that machine evidence cannot make.
They are recorded directly from the active Codex conversation. JStack v0.8.2
does not use approval challenges, signing keys, tokens, mailbox responses, or
terminal commands.

The Lead must show the exact program, gate, proposed decision, approver
identity, approver role, and bounded reference before resolution. The named
person must explicitly approve or reject in the conversation. Silence,
inference, a broad earlier request, or an agent-generated statement is not a
decision.

## Resolve A Gate

1. Inspect `jstack_program_status` and identify the pending human gate.
2. Show its description, required roles, quorum, freshness limit, and effect on
   downstream phases.
3. Obtain an explicit `approved` or `rejected` decision in the active
   conversation.
4. Call `jstack_program_gate_resolve` with:
   - the exact `program_id` and `gate_id`;
   - a stable lowercase `approver_id`;
   - one `approver_role` required by the gate;
   - the exact decision;
   - a bounded, non-secret `approval_reference`; and
   - a fresh stable `operation_id`.
5. JStack binds the server-derived decision record to the current program
   contract and gate digest, applies its freshness window, stores only the
   reference digest, and updates role/quorum coverage.

Multiple roles or quorum requirements need distinct approver identities. A
fresh rejection blocks the gate. Expired decisions become pending again.

## Trust And Operating Rules

- The record is an auditable caller-supplied decision, not cryptographic proof
  of identity, enterprise SSO, or legal non-repudiation.
- Never invent an approver, role, reference, or decision.
- A new contract or gate digest invalidates prior gate decisions.
- Replacing a decision after dependent work completed invalidates downstream
  proof.
- A human decision never substitutes for machine criteria, security evidence,
  launch assurance, release review, or external evidence.
- Repository, Git, provider, deployment, and production actions use explicit
  user scope plus normal Codex/provider permissions. JStack adds no custom
  approval token or terminal ceremony.
- A wait can last indefinitely in wall time while the active-time budget stays
  paused; freshness still applies when work resumes.
