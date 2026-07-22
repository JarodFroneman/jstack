# ADR 0006: Exact External-Action Authorization Boundary

- Status: Accepted
- Date: 2026-07-21
- Target release: 0.7.0

## Context

JStack 0.6 separated evidence from release authority in prose and readiness
results, but an outer agent could still infer authority from broad instructions
such as approving a remediation phase or asking it to "deploy". In the
motivating failure class, an implementation phase that mentioned creating a
private repository was approved as part of a larger wave and an outer executor
created and pushed that repository. The audit itself was read-only; the missing
control was an exact action boundary after planning.

Caller booleans and free-text approval references are insufficient because the
same caller that inferred the action can populate them. Completion receipts are
also unsuitable because they prove evidence state, not accountable intent.

## Decision

JStack will default to local-only and classify eleven operations as separate
protected actions. Each authorization contains exactly one action. A server
challenge binds the complete external target, current Git/workspace/policy
subject, attached branch, complete remote snapshot, MCP session, named
identity, role, reference digest, nonce, and a maximum ten-minute policy
window. A configured human signs the canonical payload outside Codex.

Authorization and consumption revalidate the complete subject. Consumption is
destructive and produces a maximum 60-second permit for one operation. Replay,
retry, action substitution, provider/visibility/remote/ref/commit/environment
drift, expiry, or state change requires a new challenge.
Push intents distinguish an exact branch-only operation
(`tag=not-applicable`) from an exact tag-only operation. The selected local
branch or tag must resolve to the authorized full commit before the challenge,
authorization, and consumption can succeed.

The five existing command surfaces adopt the boundary. Audit cannot enter the
authorization lifecycle. Loop and program contracts retain every protected
action as blocked regardless of phase or completion status. Release readiness
remains evidence and always reports execution authority as false.

## Consequences

- Local development remains unchanged until a protected action is requested.
- Even local commits require exact signed authority.
- Multi-step release work requires multiple human decisions, one per action.
- Annotated release tags use separate local-tag creation, exact tag-only push,
  tag CI, and release-creation decisions.
- A failed provider call cannot be retried under the consumed permit.
- Identity configuration and operator signing add deliberate friction.
- The protocol blocks accidental or inferred authority inside compliant JStack
  workflows, but it is not an OS-level interceptor. Provider protections and
  host tool restrictions remain necessary against bypass or account compromise.
- Existing loop/program receipts and release-readiness results cannot be
  promoted into action permits.

## Rejected Alternatives

1. Treat `ship`, `deploy`, or `release` as blanket authority. These terms omit
   exact provider, visibility, repository, refs, commit, and environment.
2. Authorize a whole remediation wave. Phase scope can contain several
   materially different external mutations.
3. Reuse release readiness as permission. Evidence sufficiency and human
   authority are different facts.
4. Let Codex sign the challenge. That collapses requester, approver, and
   executor into the same inference path.
5. Add a sixth command. The boundary must apply to every existing workflow,
   not depend on users selecting a special command.
