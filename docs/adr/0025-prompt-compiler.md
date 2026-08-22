# ADR 0025: Two-Stage Prompt Compiler

- Status: Accepted
- Decision date: 2026-08-21
- Approval amendment: 2026-08-22
- Target release: 0.10.0-beta.4; approval amendment: 0.10.0-beta.4.1
- Extends: [ADR 0010](0010-adaptive-context-gate.md) and [ADR 0003](0003-goal-readiness-gate.md)

## Context

Users often ask for engineering work in short product language: "fix the
calendar", "make the login better", or "deploy this". JStack already inspects
the repository, attributes facts, asks at most three material questions, and
binds a normalized brief to planning. It did not, however, produce a
machine-checkable authority envelope before inspection or a versioned,
traceable execution prompt after inspection.

A one-pass rewrite cannot safely fill this gap. Before inspection it cannot
know repository facts; after inspection it is too late to prove that the raw
request's task mode and authority were preserved at intake. A second
independent questionnaire would duplicate the Adaptive Context Gate and make
clear work slower.

## Research And Licence Boundary

The design review used these sources only to identify general techniques:

| Source | Pinned revision | Licence | JStack use |
| --- | --- | --- | --- |
| DAIR.AI Prompt Engineering Guide | `57673726396dd94acb23bdb1e67f27c78ee85a8e` | MIT | Research into direct instructions, prompt elements, chaining, evaluation, factuality, and adversarial prompting. No source text or code is copied. |
| Nir Diamant Prompt Engineering | `1d28822e826afc1f267da038e9cd677449ecfe86` | Custom non-commercial | General-technique research only. No code, notebooks, prompts, examples, wording, or repository structure is copied or adapted. Commercial reuse requires separate legal permission. |

JStack's implementation and wording are original and standard-library only.
If future work copies or adapts MIT-licensed material, its copyright and licence
notice must be added. Any reuse from the Nir Diamant repository requires
verified permission and legal review first.

## Alternatives

1. String-to-string rewriting is easy but untyped, hard to diff, and prone to
   scope invention.
2. A multi-model chain can improve difficult synthesis but adds latency,
   nondeterminism, wallet risk, provider disclosure, and new failure modes.
3. A deterministic template alone is cheap but cannot distinguish sourced
   facts, requirements, or authority.
4. Replacing context readiness would discard a mature question and receipt
   boundary.
5. A separate intake command would fragment the six-workflow product surface.

The selected design is a schema-first deterministic compiler integrated with
the existing gate. Model assistance is deferred behind a future versioned
contract and must never silently replace deterministic compilation.

## Decision

### One Canonical Tool, Two Stages

Add canonical-only `jstack_prompt_compile`; add no slash command, role, model
SDK, network client, or `gstack_*` alias.

Stage A, `stage="intent"`, is the first JStack workflow call:

- retain the raw request only in call memory;
- hash its exact UTF-8 bytes;
- classify the requested task mode and explicit authority;
- extract constraints, non-goals, named URLs, paths, and platforms;
- expose material ambiguity without inventing repository facts;
- return `jstack.prompt-intent.v1` and a short-lived digest-only receipt;
- perform no project resolution, file read, edit, command, Git action, external
  action, release, deployment, or production mutation.

Stage B, `stage="grounded"`, runs after authorized read-only inspection:

- require the exact Stage A contract and receipt;
- bind the current project, Git HEAD/fingerprint, policy, workflow, risk,
  compiler version, and template version;
- merge source-labelled repository, policy, external-evidence, user, inference,
  and recommended-assumption summaries;
- reject inferred or recommended content promoted to a required requirement;
- reuse the Adaptive Context Gate and its three-question maximum;
- return `jstack.prompt-compilation.v2`, a fixed-format Codex prompt, a normal
  context-readiness result, and an internal preview receipt when context is
  ready;
- require the complete rendered prompt to be shown to the user and withhold
  planning and compilation receipts until the exact prompt is explicitly
  approved in the active conversation;
- invalidate approval when a revision changes the rendered prompt, grounding,
  task mode, authority, project, policy, compiler, or template binding.

The official workflow first presents Stage B's complete prompt. An approval-
bound second Stage B response supplies the nested `readinessReceipt` and
`normalizedBrief` to planning. Loop and Program goal-readiness receipts also
bind the exact approved compilation digest. The original v1 schema remains
published for compatibility but is no longer emitted by the current compiler.
Existing direct callers of
`jstack_context_readiness`, Loop, or Program pass through a deterministic
compatibility compiler; that bridge cannot claim that Stage A preceded host
inspection.

### Task Mode And Authority

The compiler distinguishes explain, research, plan-only, read-only audit,
diagnose-only, implement, test, review, fix, commit, push, open pull request,
deploy, production mutation, and other external action. Questions about an
action do not authorize it. Plan, explanation, research, diagnosis, and
read-only audit suppress write and external-action authority even when the
subject mentions deployment. Implementation can authorize edits and tests but
never implies commit, push, pull request, merge, release, or deployment.

Receipts are evidence, never execution permission. Host permissions and the
user's explicit instruction remain authoritative.

### Rendering And Traceability

The versioned renderer separates:

- authority boundary;
- normalized goal;
- explicit constraints and non-goals;
- quoted source-labelled context;
- traced requirements;
- in-scope and out-of-scope components;
- acceptance, verification, and rollback expectations;
- unknowns and contradictions;
- fixed execution and output rules.

Every material requirement has one source kind: explicit user, repository,
policy, external evidence, disclosed inference, or recommended assumption.
Unsupported required additions fail. Repository and external content are
rendered as data, not instructions. No hidden chain-of-thought is requested or
stored.

### Security And Privacy

- Reject credential-like raw requests and grounded values before receipts.
- Cap raw requests at 50,000 characters, rendered prompts at 40,000, and all
  collections at bounded counts and item sizes.
- Use closed public JSON Schemas and canonical SHA-256 digests.
- Keep raw prompts, source contents, secrets, messages, tool arguments, model
  output, and hidden reasoning out of receipts and telemetry.
- Bind receipts to session, expiry, project state, policy, workflow, risk,
  compiler version, and template version.
- Treat README, AGENTS, code comments, logs, web pages, screenshots, and
  documents as untrusted data unless host policy recognizes an instruction
  source.
- Make no external model call and permit no silent model fallback in Beta.4.

The MCP can withhold JStack planning receipts until the caller supplies an
approval bound to the exact preview digest. It cannot prove that a host truly
displayed the prompt or that a human, rather than an agent, supplied approval.
Official skills therefore own that conversational boundary.

The compiler cannot intercept arbitrary native Codex reads, shell commands, or
external actions that bypass JStack tools. Official skill ordering is therefore
host-compliance guidance; receipt validation is enforceable only at JStack MCP
boundaries.

### UX And Modes

Clear low-risk work asks no unnecessary context questions, but it still stops
once for the final prompt. Every official workflow displays the complete
rendered prompt and asks the user to approve it or request changes. A requested
change produces a new full preview; silence, defaults, prior build authority,
and receipts never count as approval. Users do not paste tokens, digests, or
terminal commands because preview and approval binding stays internal to the
host-to-MCP call.

`JSTACK_PROMPT_COMPILER_MODE` supports `enforced` (default), `preview`,
`shadow`, and `disabled`. Beta.4 always computes the same deterministic
contract; the mode records rollout policy. `disabled` is the explicit legacy
rollback path and removes compiler binding from newly issued readiness
receipts. Restart the MCP after changing mode.

### Invalidation

A preview or receipt is invalid after material change to the request digest,
rendered prompt digest, approval state,
accepted assumption, workflow, risk, project path, Git HEAD/fingerprint,
policy, compiler version, prompt-template version, or external-evidence digest.
Session restart and expiry also invalidate it.

## Evaluation

The release includes synthetic/de-identified cases for clear expert requests,
short vibe requests, ambiguous UI work, plan/diagnose/implement/deploy
boundaries, auth/payments/migrations/destructive work, screenshots, conflicts,
incorrect repository assumptions, prompt injection, long and multilingual
requests, and zero-to-three-question behavior.

Baseline and compiler runs must report intent preservation, unsupported and
missing requirement rates, task-mode preservation, scope inflation, question
necessity, repository-answerable question avoidance, acceptance quality,
traceability, schema validity, injection resistance, user edits, plan revision,
defects, reviewer rejection, latency, token use, and cost. Beta.4 claims the
mechanism and test coverage, not measured product uplift.

## Deferred Techniques

Chain-of-thought capture, self-consistency, tree-of-thought, large few-shot
libraries, automatic prompt optimization, and repeated model calls are not
part of Beta.4. They add cost, latency, opaque reasoning, and nondeterminism
without evidence that they improve JStack's bounded engineering workflow.
Task decomposition remains planning's responsibility after compilation.

## Consequences

The live MCP surface grows to 57 canonical tools while all 52 compatibility
aliases and all six command names remain fixed. Three public schemas and one
small standard-library module are installed with the MCP. Existing callers
continue to work through the compatibility bridge, while official workflows
gain explicit two-stage ordering and exact compiler binding.
