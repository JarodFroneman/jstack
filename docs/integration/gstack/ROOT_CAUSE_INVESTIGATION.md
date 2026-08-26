# Stage 9 — Root-Cause Investigation

## Status and authority

| Item | Value |
| --- | --- |
| Program stage | Stage 9 — Root-Cause Investigation |
| Authoritative requirements | `JSTACK_GSTACK_UNIFIED_ENGINEERING_OS_SPEC.md`, section 26 and Stage 9 |
| Reviewed upstream | `garrytan/gstack` commit `ad8400543cd9ce8d07641362db48d44a95417e33`, tree `993294b0a09f5265d2d5af6d2fb8234ae2efe450`, `investigate/SKILL.md.tmpl` |
| Adaptation | Original JStack contract and enforcement; no upstream prompt, persona, state, hook, provider, or control plane copied |
| Authority effect | None |

This stage implements the specification's **NO FIX WITHOUT SUFFICIENT
INVESTIGATION** discipline. It extends the Stage 8 methodology through the
existing Team Composer, specialist result, and dispatch paths. It does not add
a command, role, router, provider, persistence system, or action authority.

## Required flow

```text
approved fix or diagnostic task
        ↓
receipt-bound Root-Cause Investigation selection
        ↓
dispatch_phase=investigation
        ↓
problem → observed behavior → reproduction → execution trace
        ↓
falsifiable hypothesis → falsification attempt
        ↓
established root cause ──────── unresolved stop
        ↓                              │
digest-only certification             └─ no remediation
        ↓
dispatch_phase=remediation
        ↓
the original scoped writer authority, unchanged
```

Every `fix` task forces the method selection. An `implement` task receives the
gate only when its approved goal explicitly selects root-cause investigation.
Research, review, test, and diagnosis may run the investigation contract but
cannot acquire remediation eligibility unless their approved task mode already
permits source mutation.

## Contract

The canonical in-memory input is `jstack.investigation.v1`, published as
`mcp/jstack/schemas/investigation-contract.v1.schema.json`. It contains:

- a problem statement and evidence references;
- observed behavior and evidence references;
- a reproduced, intermittent, or not-reproduced state;
- one or more ordered execution-trace revisions;
- ordered, unique hypotheses with a falsification test, expected
  discriminator, result, evidence, and `sourceMutationAttempted=false`;
- an established or unresolved root-cause conclusion;
- a bounded stop reason; and
- fixed privacy and non-authority flags.

The MCP performs semantic validation beyond JSON Schema. An established cause
must end on a supported attempt, cite reproduction plus falsification evidence,
carry medium or high confidence, and use a reproducible or intermittent
symptom. A non-reproduced symptom remains unresolved for remediation gating.

The input contract is validated in memory. The signed specialist receipt
contains only `jstack.investigation.certification.v1`: the contract digest,
evidence-reference digest, counts, reproduction/root-cause state, task-mode
binding, and fixed privacy/authority flags. Raw prompt text, investigation
prose, evidence contents, source contents, command/model output, secrets, and
hidden reasoning are not retained in the certification.

## Random-loop rejection

Falsified and inconclusive attempts count as unsuccessful cycles. Hypotheses
must be distinct. At three consecutive unsuccessful cycles:

1. the contract must stop `unresolved`;
2. `stopReason` must be `hypothesis-limit`;
3. a later execution-trace revision must identify all three failed attempt
   IDs; and
4. no fourth attempt may appear in the same contract.

The next action is a revised evidence model and a genuinely changed hypothesis,
not a speculative patch. Source mutation inside the investigation contract is
always rejected.

## Dispatch enforcement

For a mutating Team Plan with Root-Cause Investigation selected:

- default/`standard` dispatch is invalid;
- `investigation` returns only `root-cause-investigator`, read-only, through a
  phase-specific `jstack.dispatch-slice.v1`;
- `remediation` requires the exact signed passing specialist receipt;
- the receipt must match goal, task mode, Team Plan, logical and physical
  assignment, canonical Investigator role, capability set, empty write scope,
  policy, Git HEAD, project fingerprint, and current server session;
- the specialist result must be successful, contain no changes, and certify
  an established cause; and
- the remediation slice excludes the completed investigator and restores only
  the original Team Plan assignments and scopes. It grants nothing new.

Diagnosis-only certification always has `remediationEligible=false`. An
unresolved, failed, partial, stale, altered, differently scoped, or
candidate-mismatched receipt cannot unlock remediation.

## Host boundary

JStack MCP can validate calls made through these contracts. It cannot prevent
a host or user from bypassing JStack and editing through unrelated native
tools. The installed Dev, Subagents, and Full Team instructions therefore
require the host to dispatch only the returned `executionSlice`. This is a
host-compliance boundary, not a claim that JStack intercepts every Codex
action.

Artifact-only projects may follow the method and report direct evidence, but
they cannot obtain a Git-bound remediation qualification receipt. Loop, Audit,
and Evidence Builder remain separate workflows until a later stage explicitly
adds a compatible versioned binding.

## Advance-gate evidence

Stage 9 passes only if tests demonstrate that:

1. every fix selects Root-Cause Investigation;
2. standard fix dispatch fails closed;
3. investigation slices contain only the read-only investigator;
4. a missing, unresolved, failed, stale, or tampered receipt blocks
   remediation;
5. three failed hypotheses require a revised trace and explicit unresolved
   state;
6. a fourth random cycle and any investigation-time source mutation are
   rejected;
7. diagnosis-only evidence cannot authorize a fix;
8. receipts retain only digest/count certification metadata;
9. existing role, task-mode, scope, policy, Git, and action boundaries remain
   intact; and
10. the six-command, 59-canonical-tool, 52-alias, standard-library-core, sync,
    provenance, and compatibility gates remain green.

No test result authorizes a commit, push, release, deployment, installation,
or production action.
