# Root-Cause Investigation Gate

Use this reference whenever the signed `methodologyPlan` selects
`root-cause-investigation`.

## Required sequence

1. Preserve the approved task mode and exact Team Plan.
2. Call `jstack_dispatch_check` with `dispatch_phase="investigation"` and
   execute only its `executionSlice`.
3. Do not edit source. Record problem, observed behavior, reproduction,
   execution trace, a unique falsifiable hypothesis, its discriminating test,
   the observed result, and the conclusion in `jstack.investigation.v1`.
4. Submit that contract only on the exact `root-cause-investigator`
   `jstack_specialist_result` call. Do not include raw prompts, source content,
   command/model output, secrets, or hidden reasoning.
5. If the cause is unresolved, stop and report the evidence gap. It is not a
   failed implementation attempt.
6. For an approved `implement` or `fix` task with an established cause, call
   `jstack_dispatch_check(dispatch_phase="remediation",
   investigation_receipt=...)` and execute only the returned remediation
   slice under the original writer scope.
7. `diagnose-only`, `research`, `test`, and `review` never become remediation
   merely because a cause was established.

Every `fix` task selects this method. `implement` uses it only when the approved
goal explicitly carries a root-cause signal.

## Three-cycle stop

After three consecutive falsified or inconclusive hypotheses:

- use distinct hypotheses;
- add a later execution-trace revision bound to all three attempt IDs;
- set the investigation and root cause to `unresolved`;
- set `stopReason="hypothesis-limit"`; and
- do not try a fourth patch or hypothesis in that contract.

Forming a future hypothesis requires a revised evidence model. Never change
source as a diagnostic experiment.

## Receipt meaning

The MCP retains only a digest/count certification. A passing receipt proves
structural validation against the current Team Plan and Git candidate; it does
not prove semantic truth and grants no write, Git, provider, external-action,
release, deployment, or production authority. JStack cannot intercept native
host activity performed outside this workflow, so host compliance with the
returned phase slice remains required.
