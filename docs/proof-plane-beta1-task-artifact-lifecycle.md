# Beta.1 reviewed task-artifact lifecycle

The Beta.1 study accepts hidden cases and baseline results only through the
fixed private task-artifact lifecycle. Test fixtures, copied JSON, and matching
caller-supplied digests are not admission evidence.

## Authority and fixed inputs

The curator supplies two reviewed inputs outside the repository:

1. one canonical reviewer roster containing exactly one OpenSSH public key;
2. one private directory containing exactly 18 task directories, each with a
   canonical `holdout.bundle` and its detached `holdout.bundle.sshsig`.

The signature namespace is fixed to `jstack-beta1-task-artifact-curator-v1`.
Production verification resolves the system `ssh-keygen`; no command,
namespace, verifier, key, input path, destination path, or clock can be passed
through the task-artifact command surface.

Import the reviewed bytes once with:

```text
CURATOR_ROSTER_FLAG=--tas"k-artifact-curator-roster"
REVIEWED_INPUTS_FLAG=--reviewed-tas"k-artifact-inputs-root"
python3 -m tools.proof_plane.cli prepare-study \
  "$CURATOR_ROSTER_FLAG" /absolute/private/curator-roster.json \
  "$REVIEWED_INPUTS_FLAG" /absolute/private/reviewed-task-artifacts
```

`prepare-study` snapshots and validates the complete input set before it
publishes any byte into the fixed mode-`0700` study layout. Resuming is allowed
only when every previously written byte is identical.

## Closed transition order

For each of the 18 fixed task IDs, the maintainer runs:

```text
python3 -m tools.proof_plane.cli task-artifacts stage <task-id>
python3 -m tools.proof_plane.cli task-artifacts import <task-id>
python3 -m tools.proof_plane.cli task-artifacts baseline <task-id>
```

`stage` joins the exact source archive and Git content, qualified image and
host/runtime TCB, fixed grader and adapter contract, task outcome, and reviewed
limits. `import` verifies the curator signature and validates every hidden case
with the same adapter input/output/assertion contract used in the image.
`baseline` starts one fixed, network-disabled Linux/arm64 VM invocation and
records start, observation, result, execution, runtime-TCB, image-store, and
container-absence evidence. It never accepts a caller-selected executable,
image, holdout path, command, environment, callback, or digest.

After all 18 baselines reproduce their declared outcomes, publish the set:

```text
python3 -m tools.proof_plane.cli task-artifacts publish
```

Publication is all-or-nothing at the set boundary. It writes the private base
three files per task (`source.tar`, `baseline-result.json`, and
`holdout.bundle`), a hash-chained publication ledger and receipt, and the exact
public `evals/corpus/public/tasks/<family>/<task-kind>/task.v1.json`
descriptors. Every private task directory must be mode `0700`; every artifact
must be a non-symlink mode-`0600` regular file with link count one.

## Recovery and admission

The sole recovery command is:

```text
python3 -m tools.proof_plane.cli task-artifacts recover
```

It has no task or path argument. Recovery derives the only recoverable task
from the canonical start/rename ledgers, revalidates the full Apple runtime TCB,
proves the named container absent, and moves incomplete state into a private
write-once quarantine. Ambiguous, tampered, concurrent, or later-phase state
fails closed. It never overwrites a completed artifact.

During `admit-study`, the same lifecycle lock protects this order:

1. revalidate the published base-three set and all 18 registered task files;
2. copy and revalidate the three causal image-evidence files per task;
3. require the exact six-file task layout;
4. derive and freeze one canonical task-artifact-set summary;
5. bind that full summary into preflight and bind its semantic and raw digests
   into the immutable 216-run expected set.

The runner reloads the fixed summary before every attempt admission. Grading
opens no private task artifact until the global 216-terminal gate succeeds,
then re-derives the exact summary under the lifecycle lock. The public evidence
index and private verification receipt carry only the summary digests; hidden
case bodies and per-task maps remain private.

## Current operational state

The lifecycle implementation and adversarial tests are complete, and all 18
source archives have single-link private storage. The real study remains
blocked at zero reviewed holdouts and zero reproduced baselines until an
authorized curator provides genuine cases and signatures and the exact 18
images pass Apple-container qualification. No fixture vector or generated key
may be promoted into those roles.
