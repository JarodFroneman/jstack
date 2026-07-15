# JStack Loop Protocol

## Execution Composition

| Mode | How it is selected | Iteration owner | Escalation rule |
| --- | --- | --- | --- |
| `single-lead` | Default or explicit JStack Dev | One Lead Engineer | Stop and ask before adding agents |
| `smart-subagents` | Explicit JStack Subagents request | Lead plus normally 2-3 specialists | Validate every dispatch packet |
| `full-team` | Explicit JStack Full Team request | Lead coordinating 11 roles in waves | Never infer from task size |

JStack Audit is not a fourth editing mode. It is an independent, read-only
verifier that may satisfy an audit acceptance criterion.

## Autonomy Levels

| Level | Boundary | Typical use |
| --- | --- | --- |
| `L0` | Design only, no repository writes | Goal and loop design |
| `L1` | Read and evaluate, no repository writes | Investigation or audit |
| `L2` | Supervised implementation inside approved paths | Default feature and repair work |
| `L3` | Explicitly approved, low-risk, machine-verifiable work in a linked worktree | Mature autonomous maintenance |

All write-capable loops start from a clean Git state. One write-capable loop
holds the lease for that Git checkout at a time; separately linked worktrees
are separate isolated checkouts. L3 requires bounded paths plus QA, security,
audit, and deterministic review criteria. Every L3 path starts with a literal
top-level repository entry.

Path globs are segment-aware. `src/*` matches one level under `src`, while
`src/**` explicitly includes every descendant. Root-wide wildcard scopes are
rejected for L3. Literal backslash and control-character Git filenames are not
representable and fail closed instead of being normalized.

## Goal Readiness Gate

`jstack_loop_goal_readiness` is mandatory before start and before every
material contract revision. It accepts partial intake so the agent can inspect
first and ask only for facts it cannot establish safely. It returns the full
gap list and at most three targeted blocking questions per round.

The candidate `goal_context` records:

- domain statement and one or more supported domain tags;
- affected stakeholders, current state, and observable desired outcome;
- constraints, non-goals, assumptions, and unresolved questions;
- repository, user, runtime, or external context sources;
- niche-specific correctness and failure requirements; and
- every material field inferred by the agent rather than stated directly.

Repository sources must be existing regular files inside the Git root. Path
traversal and symlink references fail closed. Product/UI, security/compliance,
financial/data, production/operations, research/content, and unknown domains
require explicit niche requirements instead of generic software assumptions.

The gate requires exact-digest user confirmation when the contract contains
material inference, assumptions, non-blocking unknowns, medium-or-higher risk,
L3 autonomy, broad outcome language, or a confirmation-sensitive domain. The
agent must present the returned preview, reasons, and `readinessDigest`; it may
submit `confirmed_readiness_digest` and `confirmation_reference` only after a
real user confirmation. A model-authored confirmation reference is invalid
process even if it passes schema validation.

A successful assessment issues a short-lived, session-local receipt bound to
the semantic contract input, context digest, Git HEAD and fingerprint, policy,
tool version, and, for a revision, loop ID plus prior contract digest. The
receipt authorizes only loop start or that exact revision. It does not approve
implementation, protected files, push, deployment, or release.

Material changes to the goal, criteria, execution mode, autonomy, risk, paths,
blocked actions, limits, token budget, or goal context require a new assessment
and receipt. Named human-criterion updates and explicit retry/resume approvals
may carry the existing readiness decision when the semantic contract is
unchanged. Pre-0.4.1 loop state remains readable; its first material revision
must supply a complete context and current readiness receipt.

## Acceptance Criteria

Use stable IDs and observable verifiers:

```json
[
  {
    "id": "tests",
    "description": "The focused Python suite passes.",
    "verifier": {"type": "qa", "commandKey": "python:unittest"}
  },
  {
    "id": "security",
    "description": "The bounded security scan is complete and clean.",
    "verifier": {"type": "security"}
  },
  {
    "id": "review",
    "description": "Deterministic diff hygiene passes.",
    "verifier": {"type": "review"}
  }
]
```

Verifier contracts:

- `qa`: Requires a current passing JStack QA receipt for `commandKey`.
- `security`: Requires a current complete passing security receipt.
- `audit`: Requires a current passing audit receipt for the specified profile.
- `review`: Uses server-derived Git change evidence and `git diff --check`.
- `artifact`: Requires an exact repository file and optionally an exact SHA-256.
- `human`: Requires a named approval key added by an approved contract revision.

Do not use subjective criteria such as "looks good," "enterprise quality," or
"the user will probably accept it." Split those into observable behavior,
tests, artifacts, and an explicit approval where judgment is unavoidable.
Artifact verification is bounded to 20 criteria, 25 MB per file, 100 MB in
aggregate, and a 30-second collection window.

## Circuit Breakers

The default contract stops for review after:

- 12 iterations;
- 3 checkpoints with no project or criterion progress;
- 2 repetitions of the same failure signature;
- 120 elapsed minutes;
- 50 changed files;
- an observed project-fingerprint oscillation;
- any policy, protected-path, or scope violation.

Changing the goal, criteria, staffing, autonomy, risk, scope, limits, token
budget, or goal context requires fresh readiness, creates a new contract
revision, and invalidates prior completion state. Never disguise a revision as
another iteration.

`needs_approval` is a protocol pause: checkpoint and finalization calls are
rejected until an approved revision is recorded. A named human approval update
must correspond to a human criterion. For a retry that does not change the
contract, record an explicit resume approval reference. Policy or JStack tool
version drift also pauses for revision; a scope, hidden-index, protected-path,
or policy violation stops the loop.

The original baseline commit must remain the exact merge base of `HEAD`.
Branch switches, resets, and rebases that invalidate that ancestry cannot
silently broaden the evidence subject.

## Goal Semantics

The JStack event log is not Codex Goal mode. It supplies durable evidence and a
decision protocol. Codex Goal mode supplies continuation across turns.

- Create a native goal only after the loop contract is accepted.
- Complete only with a current JStack completion receipt.
- Mark blocked only after the same blocker persists for three consecutive Goal
  turns.
- Treat user stop, approval wait, policy stop, and budget exhaustion as distinct
  outcomes.
- Preserve sandbox, approval, Git, release, and deployment boundaries on every
  iteration.
