# External-Action Authorization Boundary

JStack 0.7 defaults every project to local-only work. Completing code, tests,
an audit, a loop, a program, a remediation wave, or a release-readiness check
does not grant permission to change Git history or an external system.

## Protected Actions

Each action below is a separate authorization subject:

| Action ID | Required signed-local role |
| --- | --- |
| `repository_create` | `repository-owner` |
| `remote_add` | `repository-owner` |
| `remote_change` | `repository-owner` |
| `commit` | `source-owner` |
| `push` | `repository-owner` |
| `pull_request_create` | `repository-owner` |
| `merge` | `merge-owner` |
| `tag_create` | `release-owner` |
| `release_create` | `release-owner` |
| `deploy` | `deployment-owner` |
| `production_mutation` | `production-operator` |

`implement`, `build`, `finish`, `ship`, `deploy`, and `release` are goal words,
not authorization records. The same is true of task approval, phase approval,
remediation approval, staffing approval, program human gates, audit passes,
release readiness, and loop/program completion receipts.

## Exact Intent

One challenge contains one action and all of these fields:

- provider;
- owner and repository;
- visibility;
- remote name and exact remote URL;
- branch;
- tag, or the literal `not-applicable` when the action has no tag;
- full 40- or 64-character Git commit ID;
- target environment;
- absolute project path, current HEAD, complete workspace fingerprint, policy
  digest, JStack version, MCP session, attached branch, and remote snapshot;
- named approver, required role, approval-reference digest, issue time, expiry,
  and nonce.

Missing fields, wildcards, placeholders, detached HEAD, abbreviated commits,
unsafe refs, embedded URL credentials, ambiguous remotes, provider/URL identity
mismatch, or action-incompatible fields fail before a challenge is created.

For local `commit` authorization, use `provider=local-git`, `owner=local`, the
project directory name as `repository`, `visibility=local-only`,
`remoteName=not-applicable`, `remoteUrl=not-applicable`, the current branch,
`tag=not-applicable`, current HEAD as `exactCommit`, and
`targetEnvironment=local`. A commit authorization is bound to its exact parent
HEAD and complete staged/unstaged/untracked fingerprint.

Repository-provider actions use an exact non-local visibility and
`targetEnvironment=repository`. `tag_create` and `release_create` require an
exact tag. Deployment environments are exact names; `production_mutation`
requires an environment beginning with `production`.

A `push` challenge is also ref-kind exact. `tag=not-applicable` authorizes
only the named branch, and that local branch tip must resolve to
`exactCommit`. Supplying an exact tag authorizes only that tag, and the local
tag must peel to `exactCommit`. Create, push, and release a version tag as
three separately signed actions; wait for tag CI before release publication
when the repository requires it.

## Lifecycle

1. The accountable Lead calls `jstack_external_action_challenge` for one exact
   action. This writes private challenge and approval-request state but grants
   no authority.
2. JStack returns the full target, SHA-256 challenge digest, private request
   path, and a short `approvalCommand`. Token paste is not required.
3. The named operator runs that command in their own terminal, reviews every
   displayed field, and types `APPROVE ONCE`. The helper signs outside Codex,
   writes an owner-only response, and never prints the signed capability.
   Codex must not run the helper, access the private key, fabricate a response,
   or treat silence as approval.
4. `jstack_external_action_authorize` collects the response by authorization
   ID and verifies the configured identity,
   required role, signature, canonical payload, challenge record, expiry, MCP
   session, Git/workspace/policy state, branch, remotes, provider, and target.
5. Immediately before execution, the Lead obtains a fresh provider observation
   containing the same complete target, existence precondition, evidence
   source, and observation time.
6. `jstack_external_action_consume` revalidates everything, records destructive
   one-time consumption, and returns a permit valid for at most 60 seconds.
7. The executor performs that exact operation at most once. A failure, retry,
   changed argument, next action, expired permit, or any drift requires a new
   challenge and signature.

Challenge, approval-mailbox, and authorization state lives under
`~/.jstack/external-actions/<project>/` with private permissions and a
session-keyed integrity seal. A receipt is invalid after MCP restart, project
or policy change, HEAD/workspace change, branch or remote change, expiry, or
first consumption. Restoring an older state file cannot replay a consumption
inside the same MCP session.

## Configure Identities

Copy `mcp/jstack/templates/jstack.external-action-identities.json` to a private
path outside every repository. Set `JSTACK_EXTERNAL_ACTION_IDENTITY_CONFIG` in
the MCP process to that path and provide at least 32 bytes in each identity's
configured key environment variable. Do not put keys in Git, policy, prompts,
chat, logs, screenshots, or MCP arguments.

The default operator flow uses the request file returned by the challenge:

```text
python sign_external_action_authorization.py \
  --request-file '/private/path/from/approvalTransport/requestFile'
```

The request supplies the configured key-environment name and approver ID. The
helper validates the canonical payload, digest, and expiry, shows the complete
action and target, requires the operator to type `APPROVE ONCE`, reads the key
only from the environment, and writes the signed response to the paired
private mailbox. It prints neither key nor token. A non-interactive operator
may supply the full `--confirm-digest`; legacy inline token output remains
available only when no response file/request mailbox is selected.

For a short site-specific command, set
`JSTACK_EXTERNAL_ACTION_APPROVER_COMMAND` in the MCP launcher to an executable
that loads the human's key and delegates to the helper. JStack then returns a
command such as `jstack-approve --request-file ...`. The accountable human
still has to run it; Codex never does.

## Read-Only And Artifact-Only Modes

JStack Audit never calls these tools. An audit can report release evidence but
cannot create authority. Artifact-only directories cannot receive a Git-bound
authorization; they may continue local inspection, editing, testing, backup,
and artifact generation while every protected action remains blocked.

Loops and programs carry every protected action as a mandatory blocked action.
Their completion receipts remain evidence only. A separately consumed permit
does not remove or rewrite the loop/program contract; it authorizes only the
single operation named in that permit.

## Enforcement Scope

This is a mandatory JStack protocol boundary: all five JStack command surfaces
forbid protected actions without a valid consumed permit, and the MCP refuses
to mint one from broad or caller-supplied approval claims. The MCP deliberately
does not expose a shell or execute provider/deployment operations.

It is not an operating-system security sandbox and cannot technically prevent
a different, non-JStack process or a compromised same-account agent from
calling `git`, `gh`, a cloud CLI, or an API directly. Enforce host tool
allowlists, provider branch protections, deployment approvals, least-privilege
credentials, and sandboxing when protection must hold against a malicious or
non-compliant executor.
