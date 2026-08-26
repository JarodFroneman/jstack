# Unified Engineering OS empirical study

This development-only Stage 19 harness preregisters 168 cells: fourteen task
classes, four conditions, and three repetitions. It is deliberately outside
the installed MCP and plugin payload.

The conditions are Base Agent, gstack, the pinned JStack baseline, and the
combined JStack candidate. The template binds the inspected upstream commits;
an executable plan additionally requires the exact combined candidate commit,
tree, and environment digest.

No study has been run by this implementation. Every metric remains
`NOT_MEASURED`, and no comparative or superiority claim is supported. The
protocol only validates metric-only result envelopes and preserves missing,
failed, blocked, and timed-out runs in the denominator. It stores no prompts,
source code, model output, command output, secrets, or reviewer identity.

The scorer is network-free and non-authorizing. It does not call a model, run
project code, install gstack, mutate Git, publish, release, or deploy.
